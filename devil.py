# -*- coding: utf-8 -*-

# !/usr/bin/env python3

import re
import os
import time
import random
import pexpect
import signal
import logging
import pdb


def GetDebugger(debugger):
    assert debugger in ['gdb', 'lldb', 'cjdb'], logging.error('Debugger of %s not supported' % debugger)
    if debugger == 'gdb':
        return 'gdb'
    elif debugger == 'lldb':
        return 'lldb'
    elif debugger == 'cjdb':
        return 'cjdb'


def getExp(child):
    if 'gdb' in child.command:
        exp = r'(.*)\(gdb\) '
    elif 'lldb' in child.command:
        exp = r'(.*)\(lldb\) '
    elif 'cjdb' in child.command:
        exp = r'(.*)\(cjdb\) '

    return [exp, pexpect.EOF, pexpect.TIMEOUT] ### return [exp, r'[#\$] ', pexpect.EOF, pexpect.TIMEOUT]


def sendcmd(child, cmd: str):
    child.sendline(cmd)
    index = child.expect(getExp(child)) ### https://stackoverflow.com/questions/10920035/python-pexpect-before-output-out-of-sync
    logging.debug('file: %s\ncommand: %s\nbefore: %s\nafter:%s\n' % (child.name, cmd, child.before, child.after))

    if index == 0:
        return child.after
    elif index == 1:
        logging.error('[pexpect.EOF]%s for command: %s' % (child.name, cmd))
        if child.signalstatus == signal.SIGSEGV:
            raise Exception('DEBSIGSEGV')
        else:
            raise Exception('PEXPECTEOF' + str(child.signalstatus))
    elif index == 2:
        logging.error('[pexpect.TIMEOUT]%s for command: %s' % (child.name, cmd))
        raise Exception('TIMEOUTPEX')


def SkippingFiles(child):
    if 'cjdb' in child.command:
        sendcmd(child, 'image list')

        filelist = ""
        # skipping files
        for line in child.before.splitlines():
            if '.so' in line:
                lib_file = line.strip().split(' ')[-1]
                if os.path.exists(lib_file):
                    filelist = filelist + " " + lib_file

        if filelist != "":
            sendcmd(child, 'settings set target.process.thread.step-avoid-libraries ' + filelist)


def InitDebugger(file: str, debugger: str):
    assert debugger in ['gdb', 'lldb', 'cjdb'], logging.error('Debugger of %s not supported' % debugger)
    deb = GetDebugger(debugger)
    if debugger == 'gdb':
        cmd = deb + ' -q'
    elif debugger == 'lldb':
        cmd = deb + ' -X'
    elif debugger == 'cjdb':
        cmd = deb + ' -X'

    child = pexpect.spawn(cmd, maxread=200000, logfile=open('mylog_'+debugger+'.txt', 'w'), encoding='utf-8', echo=False)
    index = child.expect(getExp(child))

    child.delaybeforesend = None  ### this line can fix performance issues

    if index == 1:
        if child.signalstatus == signal.SIGSEGV:
            raise Exception('DEBSIGSEGV')
        else:
            raise Exception('PEXPECTEOF' + str(child.signalstatus))
    elif index == 2:
        raise Exception('LAUNCHTIMEOUTPEX')

    if debugger == 'gdb':
        sendcmd(child, 'set style enabled off')
        sendcmd(child, 'set confirm off')
        sendcmd(child, 'set width 0')
        sendcmd(child, 'set height 0')
        sendcmd(child, 'set pagination off')
        sendcmd(child, 'set print frame-info location-and-address')
    elif debugger == 'lldb':
        sendcmd(child, 'settings set use-color false')
        sendcmd(child, 'settings set highlight-source false')
        sendcmd(child, 'settings set auto-confirm true')
        sendcmd(child, 'settings set target.process.thread.step-in-avoid-nodebug true')
        sendcmd(child, 'settings set target.process.thread.step-out-avoid-nodebug true')
        sendcmd(child, 'settings set symbols.enable-external-lookup false')
        # sendcmd(child, 'settings set frame-format \'frame #${frame.index}: ${frame.pc} at ${line.file.basename}:${line.number}:${line.column}\\n\'', file)
    elif debugger == 'cjdb':
        sendcmd(child, 'settings set use-color false')
        sendcmd(child, 'settings set highlight-source false')
        sendcmd(child, 'settings set auto-confirm true')
        sendcmd(child, 'settings set target.process.thread.step-in-avoid-nodebug true')
        sendcmd(child, 'settings set target.process.thread.step-out-avoid-nodebug true')
        sendcmd(child, 'settings set symbols.enable-external-lookup false')
        sendcmd(child, 'settings set target.max-children-count 3')

    sendcmd(child, 'file ' + file)
    return child


def GetLineTableViaImage(file_obj, file_src, debugger):
    logging.debug('[GetLinetableViaGDBImage:start]%s\n' % file_obj)
    #########################################################
    ### obtain line info via line table information https://sourceware.org/bugzilla/show_bug.cgi?id=27126
    ### $ gdb -q a.out; (gdb) start (gdb) maint info line-table
    adr_set, loc_set, pos_set, all_set = set(), set(), set(), set()
    with InitDebugger(file_obj, debugger) as child:
        if debugger == 'gdb':
            sendcmd(child, 'start')
            out = sendcmd(child, 'maint info line-table *.c')
            src = None
            for txt in out.splitlines():
                res_src = re.search(r'symtab:\s+(.*\.[c|h])\s+', txt.strip())
                if res_src:
                    src = os.path.basename(res_src.groups()[0])

                res_fra = re.search(r'[0-9]+\s+([0-9]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+Y', txt.strip())
                if res_fra:
                    num = res_fra.groups()[0]
                    adr = res_fra.groups()[1]
                    adr = hex(int(adr, 16))
                    loc = (src, num, None, adr)
                    loc_set.add(loc)
        elif debugger == 'lldb' or debugger == 'cjdb':
            out = sendcmd(child, 'image dump line-table ' + file_src)
            for line in out.splitlines():
                ## matching '0x0000000000000630: /pathto/small.c:16' or '0x0000000000000630: /pathto/small.c:15:2'
                ## or '0x00000000000009de: /root/gcc-12.1.0/gcc/testsuite/gcc.c-torture/execute/pr80421.c:105:2, is_start_of_statement = TRUE'
                if debugger == 'lldb':
                    rem = re.match(r'^(0x[0-9a-f]+):\s+(.*\.[c|h]):([0-9]+)(:([0-9]+?))??.*', line)
                if debugger == 'cjdb':
                    rem = re.match(r'^(0x[0-9a-f]+):\s+(.*\.cj):([0-9]+)(:([0-9]+?))??.*', line)
                if rem:
                    adr, src, num, _, offset = rem.groups()
                    src = os.path.basename(src)
                    adr = hex(int(adr, 16))
                    loc = (src, num, offset, adr)
                    loc_set.add(loc)

    logging.debug('[GetLinetableViaImage:start]%s\n' % file_obj)
    return loc_set


def GetFileLines(file):
    count = 0
    for _, _ in enumerate(file):
        count += 1
    return count


def GetLineTableViaBreak(file_object: str, file_source: str, debugger: str):
    logging.debug('[GetLineTableViaBreak:start]\n')
    lwdi = set()
    with InitDebugger(file_object, debugger) as child: 
        totalLines = GetFileLines(file=file_source)
        for line in range(1, totalLines + 1, 1):
            sendcmd(child, 'b ' + str(line))

        if debugger == 'gdb':
            out = sendcmd(child, 'info breakpoints')
            for line in out.splitlines():
                res = re.search(r' at ' + file_source + r':([0-9]+)', line.strip())
                if res:
                    lwdi.add(res.groups()[0])
        elif debugger == 'lldb' or debugger == 'cjdb':
            out = sendcmd(child, 'breakpoint list')
            for line in out:
                line = line.strip()
                if ' [inlined] ' in line: continue
                if re.match(r'^[0-9]+.1: .*', line):
                    res = re.search(file_source + r':([0-9]+)[:,]', line)
                    if res:
                        lwdi.add(res.groups()[0])

    logging.debug('[GetLineTableViaBreak:end]\n')
    return lwdi


def GetFrameInfo(child, file_source):
    logging.debug('[GetFrameInfo for %s]start\n' % child.command)
    filename, lineno, offset, address, quadruple, fra = None, None, None, None, None, None
    if 'gdb' in child.command:
        out = sendcmd(child, 'bt -frame-info location-and-address')
        if '#0' in out:
            fra = '#0' + out.split('#1', 1)[0].split('#0', 1)[1]
            fra = fra.replace('\n', ' ')
            fra = fra.replace('\r', ' ')
            fra = fra.strip()
    elif ('lldb' in child.command) or ('cjdb' in child.command):
        out = sendcmd(child, 'frame info')
        for line in out.splitlines():
            if 'frame #0' in line:
                fra = line.strip()
                break

    if fra is None:
        logging.error('[frame info]out: %s for %s(checking)' % (out, child.command))
    else:
        if 'gdb' in child.command:
            rem = re.match(r'^#0\s+(0x[0-9a-f]+) .* at (.*\.[c|h]):([0-9]+).*$', fra)
            if rem:
                address, filename, lineno = rem.groups()
                filename = os.path.basename(filename)
                address = hex(int(address, 16))
                quadruple = (filename, lineno, offset, address)
        else:
            if 'lldb' in child.command:
                rem = re.match(r'^frame #0: (0x[0-9a-f]+) (.* )?at (.*\.[c|h]):([0-9]+)(:([0-9]+?))??$', fra)
            if 'cjdb' in child.command:
                rem = re.match(r'^frame #0: (0x[0-9a-f]+) (.*)?at (.*\.cj):([0-9]+)(:([0-9]+?))??$', fra)
            if rem:
                address, _, filename, lineno, _, offset = rem.groups()
                filename = os.path.basename(filename)
                address = hex(int(address, 16))
                quadruple = (filename, lineno, offset, address)

        if not rem and 'error' in out.lower():
            logging.error('[GetFrameInfo]%s for %s(checking)' % (out, child.command))

        if filename != os.path.basename(file_source): # ensure current stack frame is in user-defined source file
            filename = None

        if (filename is None) and (('.c' in fra) or ('.h' in fra) or ('.cj' in fra)):
            logging.error('(GDB)out: %s, fra: %s, quadruple: %s for %s (checking)' % (out, fra, quadruple, child.command))

    return filename, lineno, offset, address, quadruple


def GetRawFrameVars(lines: str) -> str:
    lines = lines.splitlines()
    for line in lines:
        yield line


def DumpFrameVars(raw) -> str:
    ans = ""
    isfirst: bool = True
    for item in raw:
        s = item.strip()
        if s.endswith('}'):
            break

        if isfirst:
            isfirst = False
        else:
            ans += ", "

        if s.endswith('{'):
            child = DumpFrameVars(raw)
            ans += s + child + '}'

        ans += " " + s + " "

    return ans


### Recursively traverse the structure layer by layer
def ParseFrameVars(raw) -> dict:
    variables = {}
    for item in raw:
        if item.strip().endswith('}'):
            break

        if ' = ' not in item:
            continue

        token_both = item.split(' = ', 1)
        token1 = token_both[1].strip()
        token0 = token_both[0].strip()

        if token1.startswith('{'):
            child = ParseFrameVars(raw)
            for k, v in child.items():
                variables[token0 + '.' + k] = v

        elif token1.endswith('{'):
            child = DumpFrameVars(raw)
            variables[token0] = token1 + child + '}'

        else:
            variables[token0] = token1

    return variables


def GetFrameVars(child):
    if 'gdb' in child.command:
        items_l = sendcmd(child, 'info locals')
        items_a = sendcmd(child, 'info args')

        items = items_l + '\n' + items_a
    else:
        items = sendcmd(child, 'frame var')

    raw = GetRawFrameVars(items)
    variables = ParseFrameVars(raw)

    return variables


def InferiorExit(child):
    if 'gdb' in child.command:
        out = sendcmd(child, 'info proc')
        if 'No current process' in out:
            return True
    else:
        out = sendcmd(child, 'process status')
        if re.search(r'Process [0-9]+ exited with status = [0-9]+', out):
            return True

    return False


def ensureInitiated(obj, key1, key2, key3, key4, value):
    if key1 not in obj:
        obj[key1] = {}

    if key2 not in obj[key1]:
        obj[key1][key2] = {}

    if key3 not in obj[key1][key2]:
        obj[key1][key2][key3] = {}

    if key4 not in obj[key1][key2][key3]:
        obj[key1][key2][key3][key4] = value

    return obj


def stepping(child, step):
    if step == 'stepl':
        cmd = 'step'
    elif step == 'stepi':
        cmd = 'stepi'
    elif step == 'random':
        if bool(random.getrandbits(1)):
            cmd = 'step'
        else:
            cmd = 'stepi'
    sendcmd(child, cmd)


def DriveToPoint(file_source: str, debugger: str, child, point, way: str, timeout: int):
    logging.debug('\n[Drive to %s via %s for %s]start\n' % (point, way))
    ###############################################
    # Prefix: run to a program point
    ###############################################
    if way == 'break':
        if point.startswith('0x'):
            if 'gdb' in debugger:
                cmd = 'b *' + point
            else:
                cmd = 'b ' + point
        else:
            cmd = 'b ' + point[0] + ':' + point[1]

        sendcmd(child, cmd)
        sendcmd(child, 'run')

        file, line, _, address, _ = GetFrameInfo(child, file_source)
        if point.startswith('0x'):
            if address == point:
                return True
        else:
            if (file == point[0]) and (line == point[1]):
                return True
    else:
        sendcmd(child, 'b main')
        sendcmd(child, 'run')

        time_start = time.time()
        file_prev = None

        while True:
            if (time.time() - time_start) >= timeout:
                raise Exception('TIMEOUTDEB')

            if InferiorExit(child):
                break

            file, line, _, address, _ = GetFrameInfo(child, file_source)

            if point.startswith('0x'):
                if address == point:
                    return True
            else:
                if (file == point[0]) and (line == point[1]):
                    return True

            if file_prev is None and file:
                file_prev = file

            if (file is None) and (file_prev is None):
                sendcmd(child, 'finish')
                continue
            
            file_prev = file
            stepping(child, way)

    return False


def Hittimes_table_update(obj, key):
    if key in obj:
        obj[key] += 1
    else:
        obj[key] = 1

    return obj


def Varvalue_table_update(obj, key, var):
    if key in obj:
        obj[key].append(var)
    else:
        obj[key] = [var]

    return obj


def SuffixStepping(file_object: str, file_source: str, child: pexpect.spawn, step: str, timeout: int):
    logging.debug('\n[SuffixStep via %s for %s]start\n' % (step, file_object))
    #################################################
    # Suffix: step by step
    #################################################
    all_set, ord_lst, frq_map, var_tbl = set([]), [], {}, {}

    adr_order_lst, adr_hittimes_tbl, adr_varvalue_tbl = [], {}, {}
    loc_order_lst, loc_hittimes_tbl, loc_varvalue_tbl = [], {}, {}
    pos_order_lst, pos_hittimes_tbl, pos_varvalue_tbl = [], {}, {}
    all_order_lst, all_hittimes_tbl, all_varvalue_tbl = [], {}, {}

    file_prev = None

    time_start = time.time()
    while True:
        if (time.time() - time_start) >= timeout:
            raise Exception('TIMEOUTDEB')

        if InferiorExit(child):
            break

        file, line, offset, address, _ = GetFrameInfo(child, file_source)

        if (file_prev is None) and file:
            file_prev = file

        if (file is None) and (file_prev is None):
            ### When previous and current stacks are both in library functions, finish to the parent stack
            if ('lldb' in child.command) or ('cjdb' in child.command):
                out_b = sendcmd(child, 'bt')
                if 'frame #1' in out_b:
                    out_f = sendcmd(child, 'finish')
                    if 'error: Could not create return address breakpoint' in out_f:
                        stepping(child, step)
                else:
                    stepping(child, step)
            else:
                sendcmd(child, 'finish')
            continue

        if file is None:
            ### when reach to library functions, step to next statement or instruction
            stepping(child, step)
            file_prev = file
            continue

        adr, loc, pos, all = address, (file, line), (file, line, offset), (file, line, offset, address)

        ### record filename, fileNo, offset, and address
        adr_order_lst.append(adr)
        loc_order_lst.append(loc)
        pos_order_lst.append(pos)
        all_order_lst.append(all)

        Hittimes_table_update(adr_hittimes_tbl, adr)
        Hittimes_table_update(loc_hittimes_tbl, loc)
        Hittimes_table_update(pos_hittimes_tbl, pos)
        Hittimes_table_update(all_hittimes_tbl, all)

        ### record variable values
        varvalue = GetFrameVars(child)
        Varvalue_table_update(adr_varvalue_tbl, adr, varvalue)
        Varvalue_table_update(loc_varvalue_tbl, loc, varvalue)
        Varvalue_table_update(pos_varvalue_tbl, pos, varvalue)
        Varvalue_table_update(all_varvalue_tbl, all, varvalue)

        ensureInitiated(frq_map, file, line, offset, address, 0)
        frq_map[file][line][offset][address] += 1
        
        if all not in all_set:
            all_set.add(all)
            ord_lst.append(all)
            ensureInitiated(var_tbl, file, line, offset, address, [])
            var_tbl[file][line][offset][address] = varvalue

        file_prev = file
        stepping(child, step)

    return {'order': ord_lst, 'frequency': frq_map, 'variable': var_tbl, 
            'adrOrder': adr_order_lst, 'adrHittimes': adr_hittimes_tbl, 'adrVarvalue': adr_varvalue_tbl, 
            'locOrder': loc_order_lst, 'locHittimes': loc_hittimes_tbl, 'locVarvalue': loc_varvalue_tbl, 
            'posOrder': pos_order_lst, 'posHittimes': pos_hittimes_tbl, 'posVarvalue': pos_varvalue_tbl, 
            'allOrder': all_order_lst, 'allHittimes': all_hittimes_tbl, 'allVarvalue': all_varvalue_tbl}


def CompleteRun(file_object: str, file_source: str, debugger: str, step: str, timeout: int):
    logging.debug('\n[CompleteRunViaGDB via %s for %s]start\n' % (step, file_object))
    with InitDebugger(file=file_object, debugger=debugger) as child:
        sendcmd(child, 'b main')
        sendcmd(child, 'run')

        SkippingFiles(child)
        res = SuffixStepping(file_object=file_object, file_source=file_source, child=child, step=step, timeout=timeout)
        return res


def OneRun(file_object: str, file_source: str, debugger: str, point: str, way: str, step: str, timeout: int):
    logging.debug('\n[OneRunViaGDB %s %s via %s for %s]start\n' % (way, point, step, file_object))
    with InitDebugger(file=file_object, debugger=debugger) as child:
        flag = DriveToPoint(file_source=file_source, child=child, point=point, way=way, timeout=timeout)
        if flag:
            res = SuffixStepping(file_object=file_object, file_source=file_source, child=child, step=step, timeout=timeout)
            return res
