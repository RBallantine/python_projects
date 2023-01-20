import csv
import tldextract as tld

file_name = '/Users/ronan/Documents/malicious_urls.tsv'
fqdn_list = []

i=1
with open(file_name) as f:
    file = csv.reader(f)

    print(file.line_num)

    for line in file:
        fqdn = tld.extract(line[0]).fqdn
        fqdn_list.append(fqdn)

with open("malicious_fqdns.txt", "w", newline='') as fq:
    writer=csv.writer(fq, delimiter=',')
    
    for item in fqdn_list:
        writer.writerow([item])
