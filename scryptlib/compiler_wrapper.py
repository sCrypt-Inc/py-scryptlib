import subprocess
from datetime import datetime
from pathlib import Path


def compile(source, **kwargs):
    asm = True
    debug = True
    optimize = False
    ast = False
    desc = False
    st = datetime.now()
    timeout = 1200
    out_files = dict()
    cmd_args = None

    if 'asm' in kwargs:
        asm = kwargs['asm']
    if 'debug' in kwargs:
        asm = kwargs['debug']
    if 'optimize' in kwargs:
        asm = kwargs['optimize']
    if 'ast' in kwargs:
        ast = kwargs['asm']
    if 'desc' in kwargs:
        desc = kwargs['desc']
    if 'timeout' in kwargs:
        timeout = kwargs['timeout']
    if 'cmd_args' in kwargs:
        cmd_args = kwargs['cmd_args']

    if not 'cwd' in kwargs:
        raise Exception('Missing argument "cwd". No working directory specified for compiler command.')
    cwd = kwargs['cwd']

    if not 'out_dir' in kwargs:
        raise Exception('Missing argument "out_dir". No output directory specified.')
    out_dir = kwargs['out_dir']

    if not 'compiler_bin' in kwargs:
        raise Exception('Missing argument "compiler_bin". Path to compiler not specified.')
    compiler_bin = kwargs['compiler_bin']

    # Assemble compiler command
    cmd_buff = [compiler_bin, 'compile']
    if asm:
        cmd_buff.append('--asm')
    if ast or desc:
        cmd_buff.append('--ast')
    if debug:
        cmd_buff.append('--debug')
    if optimize:
        cmd_buff.append('--opt')
    cmd_buff.append('-r')
    cmd_buff.append('-o')
    cmd_buff.append('{}'.format(str(out_dir.absolute())))
    if cmd_args:
        cmd_buff.append(cmd_args)

    print(cmd_buff)
    print(cwd)

    # Execute compiler
    res = subprocess.run(cmd_buff, 
            stdout=subprocess.PIPE, 
            input=source.encode('utf-8'),
            timeout=timeout,
            cwd=cwd
            ).stdout

    # If compiling on win32, the outputs will be CRLF seperated.
    # We replace CRLF with LF, to make SYNTAX_ERR_REG、SEMANTIC_ERR_REG、IMPORT_ERR_REG work.
    res = res.replace(b'\r\n', b'\n')


def compile_f(source_path, **kwargs):
    with open(source_path, 'r', encoding='utf-8') as f:
        source = f.read()

    if not 'out_dir' in kwargs:
        kwargs['out_dir'] = Path(source_path).parent

    if not 'cwd' in kwargs:
        kwargs['cwd'] = Path(source_path).parent

    compile(source, **kwargs)




