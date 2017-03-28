#!/usr/bin/env python
import collections
import boto3
import shelve
import argparse
import re
import sys
from urllib2 import urlopen
import time

ec2 = boto3.client('ec2')
resource = boto3.resource('ec2')

def build_parser():
    parser = argparse.ArgumentParser(description=
    """
    Allow or revoke inbound access for AWS security groups.
    Groups are specified by REGEX_PATTERN, or manually passed with SECURITY_GROUP
    TO_PORT defaults to FROM_PORT.
    CIDR_RANGE must be CIDR even for singles.
    """)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-r','--regex-pattern',type=str,help='regex pattern to **match** against security group GroupName. Pass ".*" for all')
    group.add_argument('-s','--security-group', type=str, help="Security group to match against, use instead of regex")
    parser.add_argument('-p','--protocol',default='tcp',type=str,help='either tcp (default) or udp')
    parser.add_argument('-f','--from-port',help='starting port number')
    parser.add_argument('-t','--to-port',help='ending port number (defaults to FROM_PORT)')
    parser.add_argument('-c','--cidr-range',type=str,help='CIDR range (e.g. 54.164.21.12/32)')
    parser.add_argument('-d','--dry-run',action='store_true',help='if specified we do nothing except see if change would have worked')
    parser.add_argument('--revoke',action='store_true',help='if specified we revoke access instead of grant access')
    parser.add_argument('-l', '--list', nargs='?', const='g', type=str, choices=['g','s'], help='If -l, list groups that match Regex (-r), pass "-l s" to list particular group settings.')
    return parser

def get_sg_regex(pattern):
    sgs = []
    name = ""
    p = re.compile(pattern)
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        if 'Tags' in sg:
            for tag in sg['Tags']:
                if tag['Key'] == "Name":
                    name = tag['Value']
                    break
        if p.search(sg['GroupName']) or p.search(sg['Description']) or p.search(name):
            sgs.append(resource.SecurityGroup(sg['GroupId']))
    return sgs

def list_groups(pattern):
    sgs = get_sg_regex(pattern)
    print "{0: <14}{1: <35}{2: <40}{3: <25}".format("Group ID","Group Name","Group Description","Group Name (Tag)")
    for sg in sgs:
        name = ""
        if sg.tags is not None:
            for tag in sg.tags:
                if tag['Key'] == "Name":
                    name = tag['Value']
                else:
                    name = ""
        print("{0: <14}{1: <35}{2: <40}{3: <25}".format(sg.group_id, sg.group_name[:34], sg.description[:39], name))

def list_group(args):
    sgroups = []

    if args.regex_pattern:
        pattern = args.regex_pattern
        sgs = get_sg_regex(pattern)
        print "{0: <4}{1: <14}{2: <30}{3: <35}{4: <25}".format("ID","Group ID","Group Name","Group Description","Group Name (Tag)")
        count = 1
        for sg in sgs:
            name = ""
            if sg.tags is not None:
                for tag in sg.tags:
                    if tag['Key'] == "Name":
                        name = tag['Value']
                    else:
                        name = ""
            print("{0: <4}{1: <14}{2: <30}{3: <35}{4: <25}".format(count,sg.group_id, sg.group_name[:29], sg.description[:34], name))
            count += 1

        checkSecurity = True
        while checkSecurity:
            resp = raw_input("Please select security group to view (1-%d): " % len(sgs))
            if resp.isdigit():
                if int(resp) <= len(sgs) and int(resp)>0:
                    sgid = int(resp) - 1
                    sgroups = sgs[sgid]
                    checkSecurity = False
                else:
                    print "Specified digit is out of range.\n"
            else:
                print "Did not specify digit.\n"
    else:
        sgroupsID = []
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            sgroupsID.append(sg['GroupId'])
        if args.security_group in sgroupsID:
            sgroups = resource.SecurityGroup(args.security_group)
        else:
            print "Error, security group of %s does not exist, use -l to list" % args.security_group
            sys.exit()

    if sgroups:
        if args.revoke:
            sgip = []
            count = 1
            print "\n{0: <4}{1: <10}{2: <10}{3: <20}{4: <9}".format("ID", "From Port", "To Port", "CIDR IP", "Protocol")
            for srange in sgroups.ip_permissions:
                for ipadd in srange['IpRanges']:
                    print("{0: <4}{1: <10}{2: <10}{3: <20}{4: <9}".format(count, srange['FromPort'], srange['ToPort'], ipadd['CidrIp'], srange['IpProtocol']))
                    sgip.append([srange['FromPort'], srange['ToPort'], ipadd['CidrIp'], srange['IpProtocol']])
                    count+=1
            checkSecurity = True
            while checkSecurity:
                resp = raw_input("Please select ID to revoke (1-%d): " % len(sgip))
                if resp.isdigit():
                    if int(resp) <= len(sgip) and int(resp)>0:
                        sgipid = int(resp) - 1
                        revokeIP = sgip[sgipid]
                        args.protocol = revokeIP[3]
                        args.from_port = revokeIP[0]
                        args.to_port = revokeIP[1]
                        args.cidr_range = revokeIP[2]
                        perms = prepare_ip(args)
                        revoke_rule([sgroups], args, perms)
                        checkSecurity = False
                    else:
                        print "Specified digit is out of range.\n"
                else:
                    print "Did not specify digit.\n"
        else:
            print "\n{0: <10}{1: <10}{2: <20}{3: <9}".format("From Port", "To Port", "CIDR IP", "Protocol")
            for srange in sgroups.ip_permissions:
                for ipadd in srange['IpRanges']:
                    print("{0: <10}{1: <10}{2: <20}{3: <9}".format(srange['FromPort'], srange['ToPort'], ipadd['CidrIp'], srange['IpProtocol']))

def revoke_rule(sgs, args, perms):
    # An example list of "Safe" IPs, which will provide warning if they are attempted to be removed
    safe_ips = {
        "1.1.1.1/32":"Example IP",
    }

    result = True

    if perms['IpRanges'][0]['CidrIp'] in safe_ips:
        valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
        result = False
        awaitResponse = True

        print "IP %s is listed in safe IPs as being: %s" % (perms['IpRanges'][0]['CidrIp'], safe_ips[perms['IpRanges'][0]['CidrIp']])
        while awaitResponse:
            response = raw_input("Do you wish to remove? (y/N): ").lower()

            if response == "":
                awaitResponse = False
                pass
            elif response in valid:
                result = valid[response]
                awaitResponse = False
            else:
                sys.stdout.write("Please respond with yes or no (y/n)\n")
    if result:
        print "Revoking rule for %s security group(s)\n" % len(sgs)
        for sg in sgs:
            try:
                print "Revoking for %s" % sg.group_id
                sg.revoke_ingress(
                    DryRun=args.dry_run,
                    IpPermissions=[perms]
                )
                print "Successfully removed IP to %s" % sg.group_id
                time.sleep(1)
            except Exception as e:
                if type(e).__name__ == "ClientError":
                    if 'InvalidPermission' in str(e):
                        print "IP Range/Port is not found in security group, cannot remove"
                    else:
                        print e
                else:
                    print e
                    return False
        print "IP Address Range revoked for all security groups"
    else:
        print "IP Address not revoked as requested"
    time.sleep(1)

def invoke_rule(sgs, args, perms):
    print "Invoking rule for %s security group(s)\n" % len(sgs)
    for sg in sgs:
        try:
            print "Invoking for %s" % sg.group_id
            sg.authorize_ingress(
                DryRun=args.dry_run,
                IpPermissions=[perms]
            )
            print "Successfully added IP"
            time.sleep(1)
        except Exception as e:
            if type(e).__name__ == "ClientError":
                if 'InvalidPermission' in str(e):
                    print "IP Range is already set for these settings, ignoring, not removing"
                else:
                    print e
            else:
                print e
                return False
    print "IP Address range invoked for all security groups\n"
    return True

def get_security_group(args):
    print "Identifying security group based on search parameters...\n"
    sgroupsID = []
    sgroups = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        sgroupsID.append(sg['GroupId'])

    if args.regex_pattern:
        pattern = args.regex_pattern
        sgs = get_sg_regex(pattern)
        print "{0: <4}{1: <14}{2: <30}{3: <35}{4: <25}".format("ID","Group ID","Group Name","Group Description","Group Name (Tag)")
        count = 1
        for sg in sgs:
            name = ""
            if sg.tags is not None:
                for tag in sg.tags:
                    if tag['Key'] == "Name":
                        name = tag['Value']
                    else:
                        name = ""
            print("{0: <4}{1: <14}{2: <30}{3: <35}{4: <25}".format(count,sg.group_id, sg.group_name[:29], sg.description[:34], name))
            count += 1

        checkSecurity = True
        while checkSecurity:
            resp = raw_input("Please select security group to update (1-%d), or CSV (1,3,5...): " % len(sgs))
            if resp.isdigit():
                if int(resp) <= len(sgs):
                    sgid = int(resp) - 1
                    sgroups.append(sgs[sgid])
                    return sgroups
            else:
                respsplit = resp.split(',')
                for respid in respsplit:
                    sgid = int(respid) - 1
                    sgroups.append(sgs[sgid])
                return sgroups
    else:
        if args.security_group in sgroupsID:
            sgroups.append(resource.SecurityGroup(args.security_group))
            return sgroups
        else:
            print "Error, security group of %s does not exist, use -l to list" % args.security_group
            sys.exit()

def prepare_ip(args):
    perms = {
        'IpProtocol': args.protocol,
        'FromPort': int(args.from_port),
        'ToPort': int(args.to_port),
        'IpRanges': [{'CidrIp':args.cidr_range}]
    }

    return perms

def main():
    parser = build_parser()

    if len(sys.argv) > 1:
        args = parser.parse_args(sys.argv[1:])
    else:
        parser.print_help()
        sys.exit()

    print("AWS Secuity Group Modifier\n")
    time.sleep(1)

    if args.list:
        if args.list == 'g':
            list_groups(args.regex_pattern)
        else:
            list_group(args)
    else:
        if not args.from_port:
            parser.error("From_port required unless listing groups (-l), or direct exchanging (-e)\n")
        if not args.cidr_range:
            parser.error("CIDR_Range required unless listing groups (-l), or direct exchanging (-e)\n")
        else:
            if args.cidr_range.lower() == "p":
                args.cidr_range =  urlopen('http://ip.42.pl/raw').read() + '/32'
                print "Specified P for Public IP grab. Set to %s\n" % args.cidr_range
                time.sleep(1)
        args.to_port = args.from_port if not args.to_port else args.to_port
        perms = prepare_ip(args)
        sgroups = get_security_group(args)

        if args.revoke:
            revoke_rule(sgroups, args, perms)
        else:
            # Inserting, not revoking
            invoke_rule(sgroups, args, perms)

if __name__ == "__main__":
    main()
