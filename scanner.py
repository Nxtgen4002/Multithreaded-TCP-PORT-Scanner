
import argparse
import csv
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy/Alt-HTTP",
}


def parse_ports(port_range):
    """Convert a port range such as 20-100 into a list."""
    try:
        parts = port_range.split("-")

        if len(parts) == 1:
            start = end = int(parts[0])
        elif len(parts) == 2:
            start, end = map(int, parts)
        else:
            raise ValueError

        if not (1 <= start <= end <= 65535):
            raise ValueError

        return range(start, end + 1)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Ports must be a valid number or range, e.g. 80 or 20-100"
        )


def scan_port(host, port, timeout):
    """Attempt one TCP connection and return its result."""
    result = {
        "host": host,
        "port": port,
        "status": "unknown",
        "service": COMMON_SERVICES.get(port, "Unknown"),
    }

    try:
        with socket.create_connection(
            (host, port), timeout=timeout
        ):
            result["status"] = "open"

    except ConnectionRefusedError:
        result["status"] = "closed"

    except (socket.timeout, TimeoutError):
        result["status"] = "filtered_or_unresponsive"

    except OSError:
        result["status"] = "connection_error"

    return result


def save_results(results, filename):
    """Export all scan results to CSV."""
    fields = ["host", "port", "status", "service"]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner"
    )
    parser.add_argument("host", help="Authorized target hostname or IP")
    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=parse_ports("1-1024"),
        help="Port or range, e.g. 80 or 1-1024",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent workers (1-500)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds",
    )
    parser.add_argument(
        "--output",
        default="scan_results.csv",
        help="CSV report filename",
    )

    args = parser.parse_args()

    if not 1 <= args.threads <= 500:
        parser.error("--threads must be between 1 and 500")

    if not 0.1 <= args.timeout <= 10:
        parser.error("--timeout must be between 0.1 and 10 seconds")

    try:
        resolved = socket.gethostbyname(args.host)
    except socket.gaierror:
        parser.error("Could not resolve the target hostname")

    ports = list(args.ports)

    print("\n=== Multithreaded TCP Port Scanner ===")
    print(f"Target: {args.host} ({resolved})")
    print(f"Ports: {ports[0]}-{ports[-1]}")
    print(f"Workers: {args.threads}")
    print("-" * 55)

    start_time = time.perf_counter()
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, args.host, port, args.timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            if result["status"] == "open":
                print(
                    f"[OPEN] {result['port']:5}  "
                    f"{result['service']}"
                )

    results.sort(key=lambda item: item["port"])
    elapsed = time.perf_counter() - start_time

    try:
        save_results(results, args.output)
    except OSError as error:
        print(f"\nCould not save CSV report: {error}")
    else:
        print(f"\nReport saved to: {args.output}")

    open_count = sum(
        result["status"] == "open" for result in results
    )

    print("\n=== Scan Summary ===")
    print(f"Ports checked: {len(results)}")
    print(f"Open ports: {open_count}")
    print(f"Duration: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
