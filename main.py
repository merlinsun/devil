# -*- coding: utf-8 -*-

# !/usr/bin/python3

import re
import os
import pdb
import pickle
import logging
import tempfile
import subprocess
import multiprocessing

from collections import OrderedDict
from optparse import OptionParser

import devil


def GetCompiler(compiler):
    if compiler == 'gcc':
        return 'gcc'
    elif compiler == 'clang':
        return 'clang'
    elif compiler == 'cjc':
        return 'cjc'


def getExperimentDir():
    expr_dir = os.path.join(os.getcwd(), 'Expr')
    os.makedirs(expr_dir, exist_ok=True)
    return expr_dir


def openDiffFile(name: str, type: str):
    expr_dir = getExperimentDir()
    rpath = os.path.join(expr_dir, type)
    os.makedirs(rpath, exist_ok=True)
    return open(os.path.join(rpath, "diff-" + name + '.txt'), 'a')


def RecordFile(file: str, flag: str, compiler: str, debugger: str):
    expr_dir = getExperimentDir()
    rpath = os.path.join(expr_dir, debugger)
    os.makedirs(rpath, exist_ok=True)

    flag_list = []
    for itema in ['ERROR', 'SEGFAULT', 'SIGABRT', 'TIMEOUT']:
        for itemb in ['CPL', 'CPLDEB', 'SANCPL', 'SANEXE', 'EXE', 'DEB']:
            flag_list.append(itema + itemb)

    if flag in flag_list + ['TIMEOUTPEX', 'PEXPECTEOF']:
        rfile = os.path.join(rpath, "files-" + flag + ".txt")
        with open(rfile, "a") as f:
            f.write("%s,%s,%s\n" % (file, compiler, debugger))
    else:
        rfile = os.path.join(rpath, "files-Other.txt")
        with open(rfile, "a") as f:
            f.write("%s,%s,%s,%s\n" % (file, compiler, debugger, flag))


### list all source files (files with specific suffix) in directory
def WalkSourceFiles(path, suffix):
    files_all = set([])
    for root, _, files in os.walk(path):
        for relFile in files:
            if relFile.endswith(suffix):
                files_all.add(os.path.join(root, relFile).strip())

    return files_all


def GetHandledFiles(path):
    files_hdl = set()
    files_lst = set()
    for path, _, files in os.walk(path):
        for file in files:
            if file.startswith('files-') and file.endswith('.txt'):
                files_lst.add(os.path.join(path, file))

    for file in files_lst:
        if 'files-ALL.txt' in file or 'files-HDL.txt' in file: continue
        with open(file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip().split(',')[0]
                if os.path.isabs(line):
                    files_hdl.add(line)
                else:
                    files_hdl.add(os.path.join(os.gecwd(), line))

    return files_hdl


### get the recorded data
def getPickleFilename(filename: str, compiler: str, debugger: str):
    pickle_path = os.path.join(getExperimentDir(), 'pickle')
    os.makedirs(pickle_path, exist_ok=True)
    return os.path.join(pickle_path, os.path.relpath(filename).replace(os.sep, '__').replace('..', '') + '__' + compiler + '__' + debugger + '.pkl')


### get line table via readelf
def GetLinetableViaRELF(file_object):
    loc_set = set() ### (file, line, address) triple with debug information

    out = os.popen("readelf --debug-dump=decodedline " + file_object + " | grep '0x'").read()

    for txt in out.splitlines():
        rem = re.match('^([/|\w]+.c)\s+([0-9]+)\s+(0x[0-9a-f]+)[0-9]+?\s+x$', txt.strip())
        if rem:
            file, line, address = rem.groups()
            loc = (os.path.basename(file), line, None, hex(int(address, 16)))
            loc_set.add(loc)

    return loc_set


def whichIsL(a1, way1: str, a2, way2: str):
    if 'stepl' in way1:
        return a1, way1, a2, way2
    return a2, way2, a1, way1


### quadruple (filename, filenumb, offset, address)
def getProgramPointByType(quadruple, point_type):
    if 'adr' in point_type:
        return quadruple[-1]
    elif 'pos' in point_type:
        return quadruple[:3]
    elif 'loc' in point_type:
        return quadruple[:2]
    elif 'all' in point_type:
        return quadruple
    else:
        raise Exception('Unimplemented')


def getObjectByType(full, point_type, var_type):
    key = point_type + var_type
    return full[key]


def compareExist(hita, hitb, waya, wayb, image, file, point_type: str, text, debugger: str, method: str, check=False):
    orderl, wayl, orderi, wayi= whichIsL(hita[point_type + 'Order'], waya, hitb[point_type + 'Order'], wayb)

    aimg = [getProgramPointByType(item, point_type) for item in image]

    for program_point in orderl:
        if check:
            if program_point not in aimg:
                continue
        if program_point not in orderi:
            if point_type is 'adr':
                with openDiffFile("Exist-" + point_type + "-" + debugger, method) as f:
                    f.write("%s, [In stepl not in stepi], wayl, %s, wayi, %s, key, %s\n" % (file, wayl, wayi, program_point))
            else:
                unpathed_filename = os.path.split(file)[1]
                if int(program_point[1]) - 1 < len(text):
                    sourcecode_line_text = text[int(program_point[1]) - 1].strip() if program_point[0] == unpathed_filename else program_point[0]
                
                if sourcecode_line_text == '}' or sourcecode_line_text == '{': continue
                with openDiffFile("Exist-" + point_type + "-" + debugger, method) as f:
                    f.write("%s, [In stepl not in stepi], wayl, %s, wayi, %s, key, %s, text, %s\n" % (file, wayl, wayi, program_point, sourcecode_line_text))
    
    if point_type is not 'adr':
        for program_point in orderi:
            if check:
                if program_point not in aimg:
                    continue
            if program_point not in orderl:
                unpathed_filename = os.path.split(file)[1]
                if int(program_point[1]) - 1 < len(text):
                    sourcecode_line_text = text[int(program_point[1]) - 1].strip() if program_point[0] == unpathed_filename else program_point[0]
                
                if sourcecode_line_text:
                    if sourcecode_line_text == '}' or sourcecode_line_text == '{': continue
                with openDiffFile("Exist-" + point_type + "-" + debugger, method) as f:
                    f.write("%s, [In stepi not in stepl], wayl, %s, wayi, %s, key, %s, text, %s\n" % (file, wayl, wayi, program_point, sourcecode_line_text))


def compareOrder(hita, hitb, waya, wayb, image, file, point_type: str, text, debugger: str, method: str, check=False):
    orderl, wayl, orderi, wayi= whichIsL(hita[point_type + 'Order'], waya, hitb[point_type + 'Order'], wayb)

    aimg = [getProgramPointByType(item, point_type) for item in image]

    orderl_unique = list(OrderedDict.fromkeys(orderl))
    orderi_unique = list(OrderedDict.fromkeys(orderi))

    if check:
        orderg_unique = list(OrderedDict.fromkeys(aimg))

        ### ensure every program location in ordl or ordi has debug info
        common = set(orderl_unique) & set(orderi_unique) & set(orderg_unique)

        ordl_n = [item for item in orderl_unique if item in common]
        ordi_n = [item for item in orderi_unique if item in common]
    else:
        ordl_n = orderl_unique
        ordi_n = orderi_unique

    if ordl_n != ordi_n:
        with openDiffFile("Order-" + point_type + "-" + debugger, method) as f:
            f.write("%s, wayl, %s, wayi, %s, stepl, %s, stepi, %s\n" % (file, wayl, wayi, ordl_n, ordi_n))


def compareHittimes(hita, hitb, waya, wayb, image, file, point_type, text, debugger: str, method: str):
    frql, wayl, frqi, wayi = whichIsL(hita[point_type + 'Hittimes'], waya, hitb[point_type + 'Hittimes'], wayb)

    for key in frql:
        if key in frqi:
            frequency_l, frequency_i = frql[key], frqi[key]
            if frequency_l > frequency_i:  ### when hit frequency in source-level debugging is larger than instruction-level
                with openDiffFile("Frequency-" + point_type + "-" + debugger, method) as f:
                    if point_type is 'adr':
                        f.write("%s, wayl, %s, wyi, %s, %s, freq(stepl):%s, freq(stepi):%s\n\n" % (file, wayl, wayi, key, frequency_l, frequency_i))
                    else:
                        if key[0] == file:
                            sourcecode_line_text = text[int(key[1]) - 1].strip()
                        else:
                            sourcecode_line_text = ''
                        f.write("%s, wayl, %s, wyi, %s, %s, %s, freq(stepl):%s, freq(stepi):%s\n\n" % (file, wayl, wayi, key, sourcecode_line_text, frequency_l, frequency_i))


def isInvalid(s: str) -> bool:
    invalid_values = ['<optimized out>', 'value may have been optimized out', '<variable not available>', '(timespec)', 'incomplete sequence', 'Could not evaluate', 'failed to read memory']
    for invalid_value in invalid_values:
        if invalid_value in s:
            return True

    if re.search(r'read memory from 0x[0-9]+ failed', s):
        return True
    return False


def unionByLast(obj, unioned_obj, floor):
    if floor >= 3:
        for key, value in obj.items():
            if key not in unioned_obj:
                unioned_obj[key] = value
    else:
        for key, value in obj.items():
            unionByLast(value, unioned_obj, floor + 1)
    return unioned_obj


def intersectByLast(obj, unioned_obj, floor):
    if floor >=3:
        yield from ((key, unioned_obj[key], value) for (key, value) in obj.items() if key in unioned_obj)
    else:
        for value in obj.values():
            yield from intersectByLast(value, unioned_obj, floor + 1)


def iterateCommonByPrefix(obja, objb, num_common, floor):
    if floor >= num_common:
        # up to 4 layers
        if floor >=4:
            return (yield ((), obja, objb))

        for value_one in obja.values():
            for value_other in objb.values():
                return (yield from iterateCommonByPrefix(value_one, value_other, num_common, floor + 1))
        return

    for key_one, value_one in obja.items():
        if key_one not in objb:
            continue
        for result in iterateCommonByPrefix(value_one, objb[key_one], num_common, floor + 1):
            yield (((key_one, )+result[0]), ) + result[1:]


# loc: (file, lineNo.)
# pos: (file, lineNo., offset)
# given two dictionary with four dimensions dictionary, iteratively obtain program point by type
def iterateCommonByType(obja, objb, point_type):
    if 'adr' in point_type:
        unioned_obja = unionByLast(obja, dict(), 0)
        result = intersectByLast(objb, unioned_obja, 0)
        return result
    elif 'pos' in point_type:
        return iterateCommonByPrefix(obja, objb, 3, 0)
    elif 'loc' in point_type:
        return iterateCommonByPrefix(obja, objb, 2, 0)
    elif 'all' in point_type:
        return iterateCommonByPrefix(obja, objb, 4, 0)
    else:
        raise Exception('Unimplemented')


def compareVarvalue(hita: dict, hitb: dict, waya: str, wayb: str, image: dict, file: str, point_type: str, text: list, debugger: str, method: str, check=False):
    sourcecode_lines = text
    varl, wayl, vari, wayi= whichIsL(hita[point_type + 'Varvalue'], waya, hitb[point_type + 'Varvalue'], wayb)

    aimg = [getProgramPointByType(item, point_type) for item in image]

    for key in varl:
        if key in vari:
            variable_tables_l = varl[key][0]
            variable_tables_i = vari[key][0]
            for variablename in set(variable_tables_l.keys()) & set(variable_tables_i.keys()):
                variable_value_l = variable_tables_l[variablename]
                variable_value_i = variable_tables_i[variablename]
                if (variable_value_l != variable_value_i):
                    sourcecode_line_text = None
                    if 'adr' not in point_type:
                        unpathed_filename = os.path.basename(file) ### split(file)[1]
                        sourcecode_line_text = sourcecode_lines[int(key[1]) - 1].strip() if os.path.basename(key[0]) == unpathed_filename else key[0]
                    with openDiffFile(point_type + "-var-" + debugger, method) as f:
                        if ('optimized out' in variable_value_l) or ('optimized out' in variable_value_i) or ('variable not available' in variable_value_i) or ('variable not available' in variable_value_l):
                            continue
                        f.write("%s, %s, %s, %s, var: %s, [wayl-value]:%s, [wayi-value]:%s, %s\n" % (
                                file, wayl, wayi, key, variablename,
                                variable_value_l, variable_value_i, sourcecode_line_text))


def compareBetweenStep(hit: dict, image: dict, waya: tuple, wayb: tuple, filename: str, text: list, debugger: str):
    cplra, optla, debuggera, stepa, lefta, pointa = waya
    cplrb, optlb, debuggerb, stepb, leftb, pointb = wayb

    ### compare the hit, oder, frequency, variable values between two different debugging strategies with same compiler, same optimizations after the execution reaches to the same point location
    assert cplra == cplrb and optla == optlb and debuggera == debuggerb and lefta == leftb and pointa == pointb, "compiler, optimization, debugger, staring location should consistent"
    assert stepa != stepb, "debugging strategies should be inconsistent"

    hita = hit[waya]
    hitb = hit[wayb]

    # compareVariable takes image of multiple opt level
    image = image[optlb]

    # Filter decides whether to distinguish (file, line, offset, address)
    for point_type in ["loc","adr","pos","all"]:
        if debugger == 'gdb' and point_type == 'pos': continue
        ### compare hit
        compareExist(hita=hita, hitb=hitb, waya=waya, wayb=wayb, image=image, file=filename, point_type=point_type, text=text, debugger=debugger, method="step")
        ### compare hit order
        compareOrder(hita=hita, hitb=hitb, waya=waya, wayb=wayb, image=image, file=filename, point_type=point_type, text=text, debugger=debugger, method="step")
        ### compare hit frequency
        compareHittimes(hita=hita, hitb=hitb, waya=waya, wayb=wayb, image=image, file=filename, point_type=point_type, text=text, debugger=debugger, method="step")
        ### compare variable values
        compareVarvalue(hita=hita, hitb=hitb, file=filename, waya=waya, wayb=wayb, image=image, point_type=point_type, text=text, debugger=debugger, method="step")


def compareBetweenOptimizationLevel(hit: dict, image: dict, waya: tuple, wayb: tuple, filename: str, text: list, debugger: str):
    cplra, optla, debuggera, stepa, lefta, pointa = waya
    cplrb, optlb, debuggerb, stepb, leftb, pointb = wayb

    assert cplra == cplrb and debuggera == debuggerb and stepa == stepb and lefta == leftb and pointa == pointb, "compiler, stepping level, debugger, staring location should be consistent"
    assert optla != optlb, "optimization should be inconsistent"
    hita = hit[waya]
    hitb = hit[wayb]

    ### compare variable values
    for point_type in ["loc","adr","pos","all"]:
        if debugger == 'gdb' and point_type == 'pos': continue
        compareVarvalue(hita=hita, hitb=hitb, file=filename, waya=waya, wayb=wayb, image=image, point_type=point_type, text=text, debugger=debugger, method="optimization")


def getOptimizationLevelsList(compiler) -> list:
    if compiler == 'gcc':
        return ['-O0', '-Og', '-O1', '-O2', '-O3']
    elif compiler == 'clang':
        return ['-O0', '-Og', '-O1', '-O2', '-O3']
    elif compiler == 'cjc':
        return ['-O0', '-O1', '-O2']


def subprocessRunCmd(cmd: str , cwd: str, timeout: int, obj: str):
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
        if proc.returncode == 0:
            return proc.stdout

        if proc.returncode == 139:
            raise Exception('SEGFAULT' + obj)
        elif proc.returncode == 134:
            raise Exception('SIGABRT' + obj)
        else:
            if 'error' in proc.stderr.decode().lower():
                raise Exception('ERROR' + obj)
            else:
                logging.error("[Check]Exception: %s with returncode of %s" % (proc.stderr.decode(), proc.returncode))
                raise Exception('ERROR-' + str(proc.returncode) + '-' + obj)
    except subprocess.TimeoutExpired:
        raise Exception('TIMEOUT' + obj)
    except Exception as e:
        logging.error('[Check]Exception %s for %s' % (str(e), cmd))
        raise e


def Check(file: str, compiler: str, debugger: str, cwd: str, timeout: int):
    assert debugger in ['gdb', 'lldb'], logging.error('Debugger of %s not supported' % debugger)

    cpl = GetCompiler(compiler)
    cmd = cpl + " -w -g " + file + ' -o ' + os.path.join(cwd, 'a.out')
    cmd = "(cd " + cwd + "; ulimit -t " + str(timeout + 2) + "; " + cmd + ")"
    subprocessRunCmd(cmd, cwd, timeout, 'CPL')

    file_san = os.path.join(cwd, "san.out")
    cmd = cpl + " -w -fsanitize=address,undefined,leak " + file + " -o " + file_san
    cmd = "(cd " + cwd + "; ulimit -t " + str(timeout + 2) + "; " + cmd + ")"
    subprocessRunCmd(cmd, cwd, timeout, 'SANCPL')

    cmd = file_san
    cmd = "(cd " + cwd + "; ulimit -t " + str(timeout + 2) + "; exec " + cmd + ")"
    subprocessRunCmd(cmd, cwd, timeout, 'SANEXE')


def CompileCJCStaticLib(filename, cwd, timeout):
    print("Compiling " + filename + "...")
    lib_filename = filename + ".a"
    if not os.path.exists(os.path.join(cwd, lib_filename)):
        cmd = "cjc -g --output-type=staticlib " + "/root/cjtest/baseFunction/" + filename + "/* -o " + lib_filename
        cmd = "(cd " + cwd + "; ulimit -t " + str(timeout + 2) + "; " + cmd + ")"
        subprocess.run(cmd, shell=True, timeout=timeout, check=True, cwd=cwd)


def Compile(file_source: str, file_object: str, compiler: str, opt: str, cwd: str, timeout: int):
    assert opt in getOptimizationLevelsList(compiler), logging.error('Optimizations of %s not supported' % opt)

    if compiler == 'cjc':
        for staticLibName in ['pkg_class', 'pkg_struct', 'pkg_enum', 'pkg_func', 'pkg_composite']:
            CompileCJCStaticLib(staticLibName, cwd, timeout)

        # compile cjtect CJDBMIMain拆分后的仓颉代码文件
        print("Compiling file_src...")
        cmd = "cjc -g " + opt + " " + file_source + " pkg_class.a pkg_struct.a pkg_enum.a pkg_func.a pkg_composite.a -o " + file_object
    else:
        cpl = GetCompiler(compiler)
        cmd = cpl + " -w -g " + opt + " " + file_source + " -o " + file_object

    cmd = "(cd " + cwd + "; ulimit -t " + str(timeout + 2) + "; " + cmd + ")"
    subprocessRunCmd(cmd, cwd, timeout, 'CPL'+opt)


def comparison(filename, compiler, debugger):
    pickle_filename = getPickleFilename(filename, compiler, debugger)
    if os.path.exists(pickle_filename):
        try:
            print("Reading Cache...")
            with open(pickle_filename, 'rb') as f:
                all_data, all_imag = pickle.load(f)
                print("Reading Cache complete")
        except Exception as e:
            print('Failed to read stored debugger execution data. Rerunning...')
            print('Exception: %s' % e)
            raise e

    with open(filename, 'r') as f:
        text = f.readlines()

    for opt in getOptimizationLevelsList(compiler):
        compareBetweenStep(all_data, all_imag,
                           (compiler, opt, debugger, 'stepl', 'break', 'main'),
                           (compiler, opt, debugger, 'stepi', 'break', 'main'),
                           filename, text, debugger)

    has_compared = []
    for opta in getOptimizationLevelsList(compiler):
        for optb in getOptimizationLevelsList(compiler):
            if opta == optb or (opta + optb in has_compared):
                continue
            has_compared.append(opta + optb)
            has_compared.append(optb + opta)
            for step in ['stepl', 'stepi']:
                compareBetweenOptimizationLevel(all_data, all_imag,
                                                (compiler, opta, debugger, step, 'break', 'main'),
                                                (compiler, optb, debugger, step, 'break', 'main'),
                                                filename, text, debugger)


def getDataFromDebugger(filename: str, compiler: str, debugger: str, cwd: str, timeout: int, startlocation=False) -> tuple:
    all_data, all_imag = {}, {}
    opts = getOptimizationLevelsList(compiler)
    ways = ['stepl', 'stepi', 'break']

    file_source = filename
    for opt in opts:
        print("Process %s, %s\n" % (filename, opt))
        fname = os.path.relpath(filename).replace('..', '').replace(os.sep, '_') ### fname = os.path.relpath(filename).split('testsuite/')[1].replace(os.sep, '_')
        file_object = os.path.join(cwd, os.path.splitext(fname)[0] + '__' + compiler + opt)
        Compile(file_source=file_source, file_object=file_object, compiler=compiler, opt=opt, cwd=cwd, timeout=timeout)

        ### imag = GetLinetableViaRELF(file_object=file_object) ### alternative approach for obtaining line table
        imag = devil.GetLineTableViaImage(file_object, file_source, debugger)
        hitl = devil.CompleteRun(file_object, file_source, debugger, "stepl", timeout)
        hiti = devil.CompleteRun(file_object, file_source, debugger, "stepi", timeout)

        all_imag[opt] = imag
        all_data[(compiler, opt, debugger, 'stepl', 'break', 'main')] = hitl
        all_data[(compiler, opt, debugger, 'stepi', 'break', 'main')] = hiti

        if startlocation:
            for way in ways:
                for point in [getProgramPointByType(item, 'loc') for item in imag] + [getProgramPointByType(item, 'adr') for item in imag]:
                    logging.debug("%s\nOneRun at %s, point, %s, by, %s\n" % (file_object, opt, point, way))

                    ahitl = devil.OneRun(file_object, file_source, debugger, point, way, "stepl", timeout)
                    ahiti = devil.OneRun(file_object, file_source, debugger, point, way, "stepi", timeout)

                    all_data[(compiler, opt, debugger, 'stepl', way, point)] = ahitl
                    all_data[(compiler, opt, debugger, 'stepi', way, point)] = ahiti

                    if (ahitl is None) or (ahiti is None):
                        rfile = os.path.join(os.path.join(getExperimentDir(), compiler, debugger), "files-FailDrive-"+ debugger + ".txt")
                        with open(rfile, "a") as f:
                            f.write("%s, opt, %s, point, %s, way, %s\n" % (file_object, opt, point, way))

    return all_data, all_imag


def task(filename: str, compiler: str, debugger: str, timeout: int):
    print("Process: %s (compiler: %s, debugger: %s)\n" % (filename, compiler, debugger))

    pickle_filename = getPickleFilename(filename, compiler, debugger)
    if not os.path.exists(pickle_filename):
        with tempfile.TemporaryDirectory() as cwd:
            try:
                if debugger == 'cjdb':
                    cwd = '/root/cjtest/baseFunction/'
                else:
                    Check(file=filename, compiler=compiler, debugger=debugger, cwd=cwd, timeout=timeout)

                all_data, all_imag = getDataFromDebugger(filename, compiler, debugger, cwd, timeout)
                print("Dump pickle file...")
                with open(pickle_filename, 'wb') as f:
                    pickle.dump((all_data, all_imag), f)
                    print("Dump pickle file complete")
            except Exception as e:
                print("Process %s with %s" % (filename, e))
                RecordFile(file=filename, flag=str(e), compiler=compiler, debugger=debugger)
                return

    if os.path.exists(pickle_filename):
        comparison(filename, compiler, debugger)


def main(source, compiler, debugger, timeout, parallel):
    rpath = os.path.join(getExperimentDir(), debugger)
    os.makedirs(rpath, exist_ok=True)

    if debugger == 'cjdb':
        with open('/root/cjtest/files-all.txt') as f:
            lines = f.readlines()
            files_all = [line.strip() for line in lines]
            files = files_all
    else:
        if source is None:
            source = "/root/gcc-12.1.0/gcc/testsuite"

        if os.path.isdir(source):
            if not os.path.isabs(source):
                source = os.path.join(os.getcwd(), source)

            files_all = WalkSourceFiles(source, ".c")
            files_hdl = GetHandledFiles(path=rpath)
            files = files_all - files_hdl
        else:
            file = source
            if not os.path.isabs(source):
                file = os.path.join(os.getcwd(), source)

            task(file, compiler, debugger, timeout)
            return

    rfile = os.path.join(rpath, "files-ALL.txt")
    if not os.path.exists(rfile):
        with open(rfile, "a") as f:
            for file in files_all:
                f.write("%s\n" % file)

    if not parallel:
        for file in files:
            task(file, compiler, debugger, timeout)
    else:
        cpu_count = multiprocessing.cpu_count()
        if cpu_count >= 3:
            processes = int(cpu_count * 3 / 4)

        pool = multiprocessing.Pool(processes)
        for file in sorted(files):
            pool.apply_async(task, args=(file, compiler, debugger, timeout,))

        pool.close()
        pool.join()

## execute main.py with the following command:
# python3 main.py --parallel -s ../gcc-12.1.0/gcc/testsuite/ --compiler="gcc"   --debugger="gdb" 
# python3 main.py --parallel -s ../gcc-12.1.0/gcc/testsuite/ --compiler="clang" --debugger="lldb"
if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-s", "--source", type=str, dest="source", help="test program or directory")
    parser.add_option("-c", "--compiler", type=str, dest="compiler", help="compiler")
    parser.add_option("-d", "--debugger", type=str, default="lldb", dest="debugger", help="debugger")
    parser.add_option("-b", "--binary", type=str, dest="binary", help="test program, absolute filename")
    parser.add_option("-t", "--timeout", type=int, default=300, dest="timeout",
                      help="Maximum time for executing and debugging a compiled binary(seconds), default: 300")
    parser.add_option("-v", "--verbose", default=3, type=int, dest="verbose",
                      help="logging verbose: 0 for Debug, 1 for info, 2 for warning, 3 for error, default: 3")
    parser.add_option("-p", "--parallel", default=False, action="store_true", dest="parallel",
                      help="enable running in parallel(will be work for directory), default: disable")

    (options, args) = parser.parse_args()

    level = logging.ERROR
    if options.verbose == 0:
        level = logging.DEBUG

    if options.verbose == 1:
        level = logging.INFO

    if options.verbose == 2:
        level = logging.WARNING

    if options.verbose == 3:
        level = logging.ERROR


    if options.compiler is None:
        if options.debugger == "gdb":
            options.compiler = "gcc"
        if options.debugger == "lldb":
            options.compiler = "clang"
        if options.debugger == "cjdb":
            options.compiler = "cjc"

    if options.debugger is None:
        if options.compiler == 'gcc':
            options.debugger = "gdb"
        if options.compiler == 'clang':
            options.debugger = "lldb"
        if options.compiler == 'clc':
            options.debugger = "cjdb"

    logging.basicConfig(filename="devil_" + options.compiler + "_" + options.debugger + ".log", level=level)

    main(source=options.source, compiler=options.compiler, debugger=options.debugger, timeout=options.timeout, parallel=options.parallel)