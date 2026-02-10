## Usage

### Basic Usage

```bash
# Single URL
./sqlidetect -u "http://example.com/page?id=1"

# From file
./sqlidetect -l urls.txt

# From stdin (pipe)
cat urls.txt | ./sqlidetect

# Combine file and single URL
./sqlidetect -l urls.txt -u "http://example.com/test?id=1"
```

### Advanced Options

```bash
# Custom concurrency (default: 10)
./sqlidetect -l urls.txt -c 20

# Custom timeout (default: 10 seconds)
./sqlidetect -l urls.txt -t 15

# Show progress
./sqlidetect -l urls.txt -p

# Custom output file (default: sqli_results.json)
./sqlidetect -l urls.txt -o results.json

# Custom User-Agent
./sqlidetect -l urls.txt -ua "Custom Bot 1.0"

# Combine all options
./sqlidetect -l urls.txt -c 30 -t 20 -p -o scan_results.json
```

## Disclaimer

This tool is for authorized security testing only. Users are responsible for obtaining proper authorization before testing any systems. Unauthorized access to computer systems is illegal.

## License

MIT License - Use at your own risk

## Credits

- PayloadsAllTheThings for SQL injection reference
- Bug bounty community for testing methodologies
