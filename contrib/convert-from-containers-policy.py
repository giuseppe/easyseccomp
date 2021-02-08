#!/usr/bin/python

# best effort conversion from a seccomp security
#policy (e.g. /usr/share/containers/seccomp.json)
#to a file understood by easyseccomp

import json
import sys

def convert_action(action, errno):
    actions = {
        'SCMP_ACT_ALLOW': 'ALLOW()',
        'SCMP_ACT_KILL': 'KILL()',
        'SCMP_ACT_KILL_THREAD': 'KILL_THREAD()',
        'SCMP_ACT_KILL_PROCESS': 'KILL_PROCESS()',
        'SCMP_ACT_NOTIFY': 'NOTIFY()',
        'SCMP_ACT_LOG': 'LOG()',
        'SCMP_ACT_TRACE': 'TRACE(%s)' % errno,
        'SCMP_ACT_ERRNO': 'ERRNO(%s)' % errno,
    }
    if action not in actions:
        raise Exception("Unknown action %s" % action)
    return actions[action]

def args_p(p):
    if 'args' not in p:
        return False

    args = p['args']
    return args is not None and len(args) > 0

def generate_and_directives(body, directives):
    if body is None or body == "":
        return
    i = 0
    for d in directives:
        print("#%sifndef %s" % (" " * i, d.upper()))
        i = i + 1
    print(body)
    for d in directives:
        i = i - 1
        print("#%sendif" % (" " * i))
    print()

def generate_or_directives(body, directives, exclude_directives):
    if body is None or body == "":
        return

    i = 0
    for d in exclude_directives:
        print("#%sifndef %s" % (" " * i, d.upper()))
        i = i + 1
    for d in directives:
        print("#%sifdef %s" % (" " * i, d.upper()))
        print(body)
        print("#%sendif" % (" " * i))
    for d in exclude_directives:
        i = i - 1
        print("#%sendif" % (" " * i))
    print()

def generate_condition(c):
    argument = "$arg%s" % c['index']
    value = c['value']
    valueTwo = c['valueTwo']

    if c['op'] == 'SCMP_CMP_MASKED_EQ':
        return "%s & %s == %s" % (argument, value, valueTwo)

    ops = {
        'SCMP_CMP_NE': "!=",
        'SCMP_CMP_EQ': "==",
        'SCMP_CMP_LT': "<",
        'SCMP_CMP_GT': ">",
        'SCMP_CMP_LE': "<=",
        'SCMP_CMP_GE': ">=",
    }
    if c['op'] not in ops:
        raise Exception("Unknown op %s" % c['op'])

    return "%s %s %s" % (argument, ops[c['op']], value)
    
        
def generate_from(policy):
    termination_statement = None
    if 'defaultAction' in policy:
        termination_statement = "=> %s;" % convert_action(policy['defaultAction'], "EPERM")

    if 'syscalls' in policy:
        for i in policy['syscalls']:
            body = ""

            errno = "EPERM"
            if 'errnoRet' in i:
                errno = i['errnoRet']
            action = convert_action(i['action'], errno)

            if args_p(i):
                for name in i['names']:
                    syscall_condition = ["$syscall == @%s" %name]
                    conditions = [generate_condition(a) for a in i['args']]
                    joined_conditions = " && ".join(syscall_condition + conditions)
                    body = "%s => %s;" % (joined_conditions, action)
            else:
                if len(i['names']) > 1:
                    syscalls = ", ".join(["@%s" % i for i in i['names']])
                    body = body + "$syscall in (%s) => %s;" % (syscalls, action)
                else:
                    body = "$syscall == @%s => %s;" % (i['names'][0], action)
            
            has_includes = 'includes' in i and len(i['includes']) > 0
            has_excludes = 'excludes' in i and len(i['excludes']) > 0

            if not has_includes and not has_excludes:
                print(body)

            exclude_directives = []
            if 'arches' in i['excludes']:
                exclude_directives = exclude_directives + ["ARCH_%s" % i for i in i['excludes']['arches']]
            if 'caps' in i['excludes']:
                exclude_directives = exclude_directives + i['excludes']['caps']

            if has_includes:
                if 'arches' in i['includes']:
                    directives = ["ARCH_%s" % i for i in i['includes']['arches']]
                    generate_or_directives(body, directives, exclude_directives)
                if 'caps' in i['includes']:
                    generate_or_directives(body, i['includes']['caps'], exclude_directives)
            elif has_excludes:
                generate_and_directives(body, exclude_directives)


    if termination_statement is not None:
        print(termination_statement)
    pass

if __name__ == "__main__":
    if len(sys.argv) == 0:
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        policy = json.load(f)

    generate_from(policy)
    sys.exit(0)
