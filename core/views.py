from django.shortcuts import render, redirect, HttpResponse

import csv

FILE_BASIC_INFO = "./core/testdata/basic.info"
FILE_EVENT_IMPORTANT = "./core/testdata/event.important"
FILE_FIREWALL_LOG = "./core/testdata/firewall.log"
FILE_IDS_LOG = "./core/testdata/ids.log"
FILE_FIREWALL_RULE = "./core/testdata/firewall.rule"
FILE_IDS_RULE = "./core/testdata/ids.rule"

FILE_PKT_ALL = "./core/testdata/pkt.all"


def indexContext():
    context = {}
    with open(FILE_BASIC_INFO, "r") as f:
        context["time_info"] = f.readline()
        context["rule_info"] = f.readline()
        context["packet_info"] = f.readline()
        context["threat_info"] = f.readline()
        context["threat_type_info"] = f.readline().split('|')
        context["threat_type_info"] = [(i, int(100 * int(i) / int(context['threat_info']))) for i in context["threat_type_info"]]

    with open(FILE_EVENT_IMPORTANT, "r") as f:
        events = []      
        for line in list(csv.DictReader(f))[-10:]:
            event = {}
            e = line['event'].split('|')
            if(e[0] == "new rule"):
                event['event'] = {"type":e[0], "rid":e[1], "action":e[2], "src":e[3], "dst":e[4]}
            elif(e[0] == "packet in"):
                event['event'] = {"type":e[0]}
            elif(e[0] == "alert"):
                event['event'] = {"type":e[0], "src":e[1], "attack_type":e[2]}
            event['timestamp'] = line['timestamp']
            event['reporter'] = line['reporter']
            events.append(event)
        for idx, event in enumerate(events[::-1]):
            event['no'] = idx + 1
        context["events"] = events[::-1]

    return context

def sidebarContext(request):
    context = {}
    collapsed = request.GET.get('collapsed')
    menuopen = request.GET.get('menuopen')

    context["collapse"] = ""
    context["icon"] = "fa-angle-double-left"
    if(collapsed and int(collapsed)):
        context["collapse"] = "sidebar-collapse"
        context["icon"] = "fa-angle-double-right"
    
    context["menuopen"] = ["menu-open" if(menuopen and int(menuopen) & 1) else "",
                           "menu-open" if(menuopen and int(menuopen) >> 1) else ""]

    return context

def firewallLogContext(request):
    context = sidebarContext(request)
    with open(FILE_FIREWALL_LOG, "r") as f:
        logs = []
        for line in list(csv.DictReader(f)):
            log = {"auto":True}
            e = line['event'].split('|')
            if(e[0] in ["new rule", "remove rule", "match rule"]):
                log['event'] = {"type":e[0], "rid":e[1]}
                if e[0] != "match rule" and e[2] == "manual":
                    log['auto'] = False
            elif(e[0] == "packet in"):
                log['event'] = {"type":e[0]}
            elif(e[0] == "alert"):
                log['event'] = {"type":e[0], "attack_type":e[1]}
            log['s_ip'] = line['s_ip']
            log['s_port'] = line['s_port']
            log['d_ip'] = line['d_ip']
            log['d_port'] = line['d_port']
            log['action'] = line['action']
            log['timestamp'] = line['timestamp']

            logs.append(log)
        context['logs'] = logs[::-1]

    return context

def idsLogContext(request):
    context = sidebarContext(request)
    with open(FILE_IDS_LOG, "r") as f:
        context['logs'] = list(csv.DictReader(f))[::-1]
    
    return context

def firewallRuleContext(request):
    context = sidebarContext(request)
    with open(FILE_FIREWALL_RULE, "r") as f:
        context['rules'] = list(csv.DictReader(f))

    return context

def idsRuleContext(request):
    context = sidebarContext(request)
    context['packets'], context['threats'] = statistic()
    
    rules = {}
    with open(FILE_IDS_RULE, "r") as f:
        for rule in list(csv.DictReader(f)):
            rules[rule['label']] = rule['action']
    
    for threat in context['threats']:
        threat['action'] = rules[threat['type']]

    context['threats'].append(context['threats'].pop(0))

    return context

def trafficStatisticContext(request):
    context = sidebarContext(request)
    context['packets'], context['threats'] = statistic()

    if(request.GET.get('target')):
        context['target'] = request.GET.get('target')  
    
    return context

def index(request):
    return render(request, 'core/index.html', indexContext())

def firewallLog(request):
    return render(request, 'core/firewall_log.html', firewallLogContext(request))

def idsLog(request):
    return render(request, 'core/ids_log.html', idsLogContext(request))

def firewallRule(request):
    return render(request, 'core/firewall_rule.html', firewallRuleContext(request))

def idsRule(request):
    return render(request, 'core/ids_rule.html', idsRuleContext(request))

def trafficStatistic(request):
    return render(request, 'core/traffic_statistic.html', trafficStatisticContext(request))

import json
def submitFirewallRule(request):
    rules = json.loads(request.body.decode('utf-8'))
    t = timestamp()
    for rule in rules:
        if(rule[6] == "NOTIMESTAMP"):
            rule[6] = t

    # truncate file to zero
    with open(FILE_FIREWALL_RULE, "w") as f:
        f.write("id,s_ip,s_port,d_ip,d_port,action,timestamp,source\n")
        f.writelines([",".join(rule)+"\n" for rule in rules])

    return HttpResponse(t)

def submitIDSRule(request):
    rules = json.loads(request.body.decode('utf-8'))
    with open(FILE_IDS_RULE, "w") as f:
        f.write("label,action\n")
        f.writelines([",".join(rule)+"\n" for rule in rules])

    return HttpResponse("")

import time
def timestamp():
    return time.strftime("%m-%d %H:%M:%S", time.localtime())

from collections import Counter
def statistic():
    with open(FILE_PKT_ALL, "r") as f:
        pkts = list(csv.DictReader(f))[::-1]
    
    threats = []
    labels = [pkt['label'] for pkt in pkts]
    counter = Counter(labels)

    colors = ["#00a65a", "#dc3545", "#dc3545", "#dc3545", "#dc3545"]
    for t in ['SAFE', 'DOS', 'R2L', 'U2R', 'PROBING']:
        if t in counter.keys():
            threat = {"type":t, "count":counter[t], "percent":format(counter[t] / len(labels) *100, ".1f"), "color":colors.pop(0)}
        else:
            threat = {"type":t, "count":0, "percent":0, "color":colors.pop(0)}
        threats.append(threat)

    return pkts, threats