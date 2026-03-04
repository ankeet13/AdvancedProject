from crawlers.crawler_forms import find_input_endpoints
from crawlers.crawler_auth import find_auth_endpoints
from crawlers.crawler_headers import check_security_headers
from crawlers.crawler_restricted import discover_restricted_endpoints


def run_all():
    print("=== Running all crawlers ===\n")

    print("[1/4] Forms crawler")
    find_input_endpoints()
    print()

    print("[2/4] Auth crawler")
    find_auth_endpoints()
    print()

    print("[3/4] Headers crawler")
    check_security_headers()
    print()

    print("[4/4] Restricted crawler")
    discover_restricted_endpoints()
    print()

    print("=== Done ===")


if __name__ == "__main__":
    run_all()