package main

import (
	"database/sql"
	l "log"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
)

var mysqlCredentials = "dmon:4dmonTest!@/dmon?charset=utf8"

func mysqlOutput(msgs chan []byte) {
	db := NewMsgLogDB(mysqlCredentials, *dbBufLenFlag)
	dbFlushTimer := time.NewTicker(time.Duration(*dbFlushFlag) * time.Millisecond)
	for {
		select {
		case <-dbFlushTimer.C:
			db.WriteMessages()
		case msg := <-msgs:
			if len(db.msgs) == cap(db.msgs) {
				db.WriteMessages()
			}
			db.msgs = append(db.msgs, msg)
		}
	}
}

// MysqlDB holds a connection to the database.
type MysqlDB struct {
	cred string
	db   *sql.DB
	err  error
	msgs [][]byte
	log  *l.Logger
}

// NewMsgLogDB returns a new MsgLogDB.
func NewMsgLogDB(cred string, bufLen int) *MysqlDB {
	return &MysqlDB{
		cred: cred,
		msgs: make([][]byte, 0, bufLen),
		log:  l.New(os.Stdout, "mysql", l.Flags()),
	}
}

// Error return the last error.
func (db *MysqlDB) Error() error {
	return db.err
}

// WriteMessages write the logging messages in the database.
func (db *MysqlDB) WriteMessages() {
	if db.db == nil || db.err != nil {
		db.tryOpenDatabase()
	}
	if db.Error() != nil {
		db.log.Fatalf("database: %+v", errors.Wrap(db.Error(), "write messages"))
	}
	if len(db.msgs) == 0 {
		return
	}
	sqlStr := "INSERT INTO dmon(stamp, level, system, component, message) VALUES "
	vals := []interface{}{}
	for _, msg := range db.msgs {
		var m Msg
		err := m.BinaryDecode(msg)
		if err == ErrUnknownEncoding {
			err = m.JSONDecode(msg)
		}
		if err != nil {
			db.log.Fatalf("unknown message encoding %d", msg[0])
		}
		stamp, _ := time.Parse("2006-01-02 15:04:05", m.Stamp)
		sqlStr += "(?, ?, ?, ?, ?),"
		vals = append(vals, stamp, m.Level, m.System, m.Component, m.Message)
	}
	sqlStr = strings.TrimSuffix(sqlStr, ",")
	stmt, _ := db.db.Prepare(sqlStr)
	_, db.err = stmt.Exec(vals...)
	if db.err != nil {
		db.err = errors.Wrap(db.err, "write to db")
		db.log.Printf("%v", db.err)
		db.db.Close()
		db.db = nil
		db.msgs = db.msgs[:0]
		return
	}
	db.msgs = db.msgs[:0]
}

func (db *MysqlDB) tryOpenDatabase() {
	db.db, db.err = sql.Open("mysql", db.cred)
	if db.err != nil {
		db.err = errors.Wrap(db.err, "open database")
		return
	}
	_, db.err = db.db.Exec(`
		CREATE TABLE IF NOT EXISTS dmon (
			mid BIGINT NOT NULL AUTO_INCREMENT,
			stamp DATETIME NOT NULL,
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
