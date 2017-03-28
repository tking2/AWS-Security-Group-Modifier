# README #

This is a currently hacked-up approach to interactively manage Security Groups on AWS. I couldn't find anything on GitHub (okay I didn't look very hard), so here is my attempt.

usage: aws_security_group.py [-h] (-r REGEX_PATTERN | -s SECURITY_GROUP | -u)
                             [-p PROTOCOL] [-f FROM_PORT] [-t TO_PORT]
                             [-c CIDR_RANGE] [-d] [--revoke] [-e] [-l]

Allow or revoke inbound access for AWS security groups. Groups are specified
by REGEX_PATTERN, or manually passed with SECURITY_GROUP TO_PORT defaults to
FROM_PORT. CIDR_RANGE must be CIDR notation

optional arguments:
  -h, --help            show this help message and exit
  -r REGEX_PATTERN, --regex-pattern REGEX_PATTERN
                        regex pattern to **match** against security group
                        GroupName. Pass ".*" for all
  -s SECURITY_GROUP, --security-group SECURITY_GROUP
                        Security group to match against, use instead of regex
  -p PROTOCOL, --protocol PROTOCOL
                        either tcp (default) or udp
  -f FROM_PORT, --from-port FROM_PORT
                        starting port number
  -t TO_PORT, --to-port TO_PORT
                        ending port number (defaults to FROM_PORT)
  -c CIDR_RANGE, --cidr-range CIDR_RANGE
                        CIDR range (e.g. 54.107.22.15/32), or P for public IP grab
  -d, --dry-run         if specified we do nothing except see if change would
                        have worked
  --revoke              if specified we revoke access instead of grant access
  -l, --list-groups     if specified we just list what security groups matched
                        the REGEX_PATTERN
## Setup
run the following command to install the tool
```bash
sudo python setup.py install
```

### Usage examples ###
```bash
# Add your public IP to the approved list, searching against the security group name, description...
aws_security_group -c P -f 443 -t 443 -protocol tcp -r "Example_Group_Name"

# Add your public IP to the approved list
aws_security_group -c P -f 443 -t 443 -protocol tcp -s <Security Group ID>

# Revoke an IP from the approved list (Note, will not return fail if the rule doesn't exist)
aws_security_group --revoke -c 192.168.1.1/32 -f 443 -t 443 -protocol tcp -s <Security Group ID>
