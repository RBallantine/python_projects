from target_domain import TargetDomain

URL = "https://dnstwister.report/search?ed=70617970616c2e636f6d"
DOMAIN = "paypal.com"

original_domain = TargetDomain(DOMAIN, URL)
original_domain.get_variants()
original_domain.enrich_variants()
original_domain.analyse_variants()
original_domain.present_results()
