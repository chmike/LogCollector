package main

func noOutput(msgs chan []byte) {
	for {
		<-msgs
	}
}
