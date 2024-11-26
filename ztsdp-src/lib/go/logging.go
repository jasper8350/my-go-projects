package ztsdp

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type MySQLHook struct {
	db *sql.DB
}

type Fields map[string]interface{}

var (
	LOGTYPE_DEBUG = 0
	LOGTYPE_INFO  = 1
	LOGTYPE_ERROR = 2
	LOGTYPE_FATAL = 3

	LOGID_SYSTEM   = "SYSTEM"
	LOGID_EVENT    = "EVENT"
	LOGID_KEYCLOAK = "KEYCLOAK"
	LOGID_IPTABLE  = "IPTABLE"

	Logger *logger
)

type logger struct {
	needDBStore bool
	DBAdmin     string
	DBPass      string
}

func NewLogger(dbStore bool, admin string, pass string) {
	Logger = &logger{
		needDBStore: dbStore,
		DBAdmin:     admin,
		DBPass:      pass,
	}
}

func NewMySQLHook(dsn string) (*MySQLHook, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	return &MySQLHook{db: db}, nil
}

func (hook *MySQLHook) Fire(entry *logrus.Entry) error {
	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	message := entry.Message
	logId := ""

	var extra []string
	f := make(map[string]interface{})
	for k, v := range entry.Data {
		if k == "logId" || k == "fileName" || k == "fileLine" {
			if k == "logId" {
				logId = v.(string)
			} else if k == "fileName" {
				entry.Caller.File = v.(string)
			} else if k == "fileLine" {
				entry.Caller.Line = v.(int)
			}
			continue
		}
		f[k] = v

		isAppend := false
		if vs, ok := v.(string); ok {
			if strings.Contains(vs, " ") {
				extra = append(extra, fmt.Sprintf("%s=\"%s\"", k, vs))
				isAppend = true
			}
		}

		if !isAppend {
			extra = append(extra, fmt.Sprintf("%s=%s", k, v))
		}
	}

	if entry.Data != nil {
		entry.Data = f
	}

	if len(extra) > 0 {
		message = message + " " + strings.Join(extra, " ")
		entry.Message = message
	}

	if entry.Level < logrus.DebugLevel {
		insertQuery := `INSERT INTO LOG (LOG_TIME, LOG_ID, LOG_MSG) VALUES (?, ?, ?)`
		_, err := hook.db.Exec(insertQuery, timestamp, logId, message)
		if err != nil {
			//writer.Err(err.Error())
		}
	}
	//return err
	return nil
}

func (hook *MySQLHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

type formatter struct {
	logrus.TextFormatter
}

func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	fileLine := path.Base(entry.Caller.File) + ":" + strconv.Itoa(entry.Caller.Line)
	return []byte(fmt.Sprintf("%s [%s] %s %s\n", entry.Time.Format("2006-01-02 15:04:05"), strings.ToUpper(entry.Level.String()), fileLine, entry.Message)), nil
}

func (l *logger) LogInit() {
	hook, _ := NewMySQLHook("")
	if l.needDBStore {
		dsn := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", l.DBAdmin, l.DBPass)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			l.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "Database connection failed.", Fields{"ERROR": err.Error()})
		}
		createDatabaseQuery := `CREATE DATABASE SDP`
		if _, err := db.Exec(createDatabaseQuery); err != nil {
			l.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "Create database failed.", Fields{"ERROR": err.Error()})
		}

		createTableQuery := `
		CREATE TABLE IF NOT EXISTS SDP.LOG (
		LOG_IDX INT(10) unsigned NOT NULL AUTO_INCREMENT,
		LOG_TIME DATETIME NOT NULL default CURRENT_TIMESTAMP,
		LOG_ID varchar(32) default NULL,
		LOG_MSG varchar(4096) default NULL,
	    PRIMARY KEY  (LOG_IDX),
		KEY TIME (LOG_TIME),
  		KEY LOGID (LOG_ID)
	);`
		db.Exec(createTableQuery)
		db.Close()

		dsn = fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/SDP", l.DBAdmin, l.DBPass)
		hook, err = NewMySQLHook(dsn)
		if err != nil {
			logrus.Fatalf("Failed to initialize MySQL hook: %v", err)
		}

	}

	lum := &lumberjack.Logger{
		Filename:   filepath.ToSlash("/var/log/ztsdp/ztsdpd"),
		MaxSize:    100,
		MaxBackups: 10,
	}

	// logrus에 MySQL hook 추가
	logrus.AddHook(hook)

	// 로그 설정
	logrus.SetFormatter(&formatter{})
	logrus.SetReportCaller(true)
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(io.MultiWriter(os.Stdout, lum))
}

func (l *logger) Log(logType int, logId string, msg string) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	fields := logrus.Fields{}
	fields["logId"] = logId
	fields["fileName"] = fileName
	fields["fileLine"] = fileLine

	log := logrus.WithFields(fields)

	l.loggingWithType(log, logType, msg)
}

func (l *logger) Logf(logType int, logId string, msg string, args ...interface{}) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	fields := logrus.Fields{}
	fields["logId"] = logId
	fields["fileName"] = fileName
	fields["fileLine"] = fileLine
	log := logrus.WithFields(fields)

	l.loggingFormatWithType(log, logType, msg, args...)
}

func (l *logger) LogWithFields(logType int, logId string, msg string, fields Fields) {
	_, fileName, fileLine, _ := runtime.Caller(1)
	fields["logId"] = logId
	fields["fileName"] = fileName
	fields["fileLine"] = fileLine
	log := logrus.WithFields(logrus.Fields(fields))

	l.loggingWithType(log, logType, msg)
}

func (l *logger) loggingWithType(logger *logrus.Entry, logType int, msg string) {
	switch logType {
	case LOGTYPE_DEBUG:
		logger.Debug(msg)
	case LOGTYPE_ERROR:
		logger.Error(msg)
	case LOGTYPE_INFO:
		logger.Info(msg)
	case LOGTYPE_FATAL:
		logger.Fatal(msg)
	}
}

func (l *logger) loggingFormatWithType(logger *logrus.Entry, logType int, msg string, args ...interface{}) {
	switch logType {
	case LOGTYPE_DEBUG:
		logger.Debugf(msg, args...)
	case LOGTYPE_ERROR:
		logger.Errorf(msg, args...)
	case LOGTYPE_INFO:
		logger.Infof(msg, args...)
	case LOGTYPE_FATAL:
		logger.Fatalf(msg, args...)
	}
}
