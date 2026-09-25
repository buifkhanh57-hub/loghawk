# perl-logparser

A classic **Perl** one-task tool: parses Apache/Nginx *common log format*
lines and prints a compact report.

## Usage
```bash
perl logparse.pl access.log
grep "GET /api" access.log | perl logparse.pl
```

## Report includes
- Total requests, bytes transferred, unique client IPs
- Status code breakdown with percentages
- Top 10 client IPs
- Requests per hour-of-day with an ASCII bar chart
