package main

import (
	"database/sql"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
)

var mysqlCredentials = "dmon:4dmonTest!@/dmon?charset=utf8"

func mysqlMsgSave(msgs chan msgInfo, statsPeriod time.Duration) {
	stats := NewStats(statsPeriod)

	db := NewMsgLogDB(mysqlCredentials, *dbBufLenFlag)
	dbFlushTimer := time.NewTicker(time.Duration(*dbFlushFlag) * time.Millisecond)
	for {
		select {
		case <-dbFlushTimer.C:
			db.WriteMessages()
		case m := <-msgs:
			if len(db.msgs) == cap(db.msgs) {
				db.WriteMessages()
			}
			db.msgs = append(db.msgs, m.msg)
			stats.Update(m.len)
		case <-stats.C:
			stats.Display()
		}
	}
}

// MsgLogDB holds a connection to the database.
type MsgLogDB struct {
	cred string
	db   *sql.DB
	err  error
	msgs []Msg
}

// NewMsgLogDB returns a new MsgLogDB.
func NewMsgLogDB(cred string, bufLen int) *MsgLogDB {
	return &MsgLogDB{cred: cred, msgs: make([]Msg, bufLen)}
}

// Error return the last error.
func (db *MsgLogDB) Error() error {
	return db.err
}

// WriteMessages write the logging messages in the database.
func (db *MsgLogDB) WriteMessages() {
	if db.db == nil || db.err != nil {
		db.tryOpenDatabase()
	}
	if db.Error() != nil {
		log.Fatalf("database: %+v", errors.Wrap(db.Error(), "write messages"))
	}
	if len(db.msgs) == 0 {
		return
	}
	sqlStr := "INSERT INTO dmon(stamp, level, system, component, message) VALUES "
	vals := []interface{}{}
	for _, m := range db.msgs {
		sqlStr += "(?, ?, ?, ?, ?),"
		vals = append(vals, m.Stamp, m.Level, m.System, m.Component, m.Message)
	}
	sqlStr = strings.TrimSuffix(sqlStr, ",")
	stmt, _ := db.db.Prepare(sqlStr)
	_, db.err = stmt.Exec(vals...)
	if db.err != nil {
		db.err = errors.Wrap(db.err, "write to db")
		log.Printf("%v", db.err)
		db.db.Close()
		db.db = nil
		db.msgs = db.msgs[:0]
		return
	}
	db.msgs = db.msgs[:0]
}

func (db *MsgLogDB) tryOpenDatabase() {
	db.db, db.err = sql.Open("mysql", db.cred)
	if db.err != nil {
		db.err = errors.Wrap(db.err, "open database")
		return
	}
	_, db.err = db.db.Exec(`
		CREATE TABLE IF NOT EXISTS dmon (
			mid BIGINT NOT NULL AUTO_INCREMENT,
			stamp DATETIME(6) NOT NULL,
			level VARCHAR(5) NOT NULL,
			system VARCHAR(128) NOT NULL,
			component VARCHAR(64) NOT NULL,
			message VARCHAR(256) NOT NULL,
			PRIMARY KEY (mid)
		) ENGINE=INNODB
	`)
	if db.err != nil {
		db.err = errors.Wrap(db.err, "open database")
		db.db.Close()
		db.db = nil
		return
	}
}
