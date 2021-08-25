import re
import json
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from enum import Enum

from . import utils


# TODO: Decide whether to keep stuff like ABI entites as dicts, or create a class for them.


CURRENT_CONTRACT_DESCRIPTION_VERSION = 3


SYNTAX_ERR_REG = r'(?P<filePath>[^\s]+):(?P<line>\d+):(?P<column>\d+):\n([^\n]+\n){3}' \
        r'(unexpected (?P<unexpected>[^\n]+)\nexpecting (?P<expecting>[^\n]+)|(?P<message>[^\n]+))'
SEMANTIC_ERR_REG = r'Error:(\s|\n)*(?P<filePath>[^\s]+):(?P<line>\d+):(?P<column>\d+):' \
        r'(?P<line1>\d+):(?P<column1>\d+):*\n(?P<message>[^\n]+)\n'
INTERNAL_ERR_REG = r'Internal error:(?P<message>.+)'
WARNING_REG = r'Warning:(\s|\n)*(?P<filePath>[^\s]+):(?P<line>\d+):(?P<column>\d+):' \
        r'(?P<line1>\d+):(?P<column1>\d+):*\n(?P<message>[^\n]+)\n'
SOURCE_REG = r'^(?P<fileIndex>-?\d+):(?P<line>\d+):(?P<col>\d+):(?P<endLine>\d+):' \
        r'(?P<endCol>\d+)(#(?P<tagStr>.+))?'


class DebugModeTag(Enum):
    FUNC_START = 'F0'
    FUNC_END = 'F1'
    LOOP_START = 'L0'


class ABIEntityType(Enum):
    FUNCTION = 'function'
    CONSTRUCTOR = 'constructor'


class SyntaxErrorEntry:
    def __init__(self, message, message_full, got, expected, position, file_path):
        self.message = message
        self.message_full = message_full
        self.got = got
        self.expected = expected
        self.file_path = file_path
        self.position = position # (line, col)


class SemanticErrorEntry:
    def __init__(self, message, message_full, position_range, file_path):
        self.message = message
        self.message_full = message_full
        self.file_path = file_path
        self.position_range = position_range # [(line, col), (line1, col1)]


class EntryErrorBase(Exception):
    def __init__(self, error_entries):
        self.error_entries = error_entries
        message = []
        for error_entry in self.error_entries:
            message.append(error_entry.message_full)
        message = '\n'.join(message)
        super().__init__(message) 


class SyntaxError(EntryErrorBase):
    pass


class SemanticError(EntryErrorBase):
    pass


class InternalError(Exception):
    pass


class CompilerResult:

    def __init__(self,
            asm=[],
            ast=None,
            dep_ast=None,
            abi=[],
            warnings=[],
            compiler_version=None,
            contract=None,
            md5=None,
            structs=[],
            alias=[],
            source_file=None,
            auto_typed_vars=[],
            source_md5=None,
            compiler_out_asm=None):
        self.asm = asm
        self.ast = ast
        self.dep_ast = dep_ast
        self.abi = abi
        self.warnings = warnings
        self.compiler_version = compiler_version
        self.contract = contract
        self.md5 = md5
        self.structs = structs
        self.alias = alias
        self.source_file = source_file
        self.auto_typed_vars = auto_typed_vars
        self.source_md5 = source_md5
        self.compiler_out_asm = compiler_out_asm

    def to_desc(self, source_map=False):
        res = {
                'version': CURRENT_CONTRACT_DESCRIPTION_VERSION,
                'compilerVersion': self.compiler_version,
                'contract': self.contract,
                'md5': self.source_md5,
                'structs': self.structs,
                'alias': self.alias,
                'abi': self.abi,
                'file': '',
                'asm': CompilerWrapper.get_asm_as_string(self.asm),
                'hex': CompilerWrapper.get_hex_script(self.asm),
                'sources': [],
                'sourceMap': [],
                'md5': self.source_md5
            }

        if source_map:
            output = self.compiler_out_asm['output']
            if len(output) == 0:
                return res
            if 'src' not in output[0]:
                raise Exception('Missing source map data in compiler results. Run compiler with debug flag.')
            sources = self.compiler_out_asm['sources']
            sources_fullpath = CompilerWrapper.get_sources_fullpath(sources)
            res['file'] = self.source_file
            res['sources'] = sources_fullpath
            res['sourceMap'] = [ item['src'] for item in self.compiler_out_asm['output'] ]

        return res


class CompilerWrapper:
    
    def __init__(self, 
                 out_dir,
                 compiler_bin,
                 debug = True,
                 optimize = False,
                 stack = True,
                 timeout = 1200,
                 cmd_args = None,
                 cwd = Path('.')):
        self.out_dir = Path(out_dir)
        self.compiler_bin = compiler_bin
        self.asm = True
        self.hex_out = True
        self.debug = debug
        self.stack = stack
        self.optimize = optimize
        self.ast = True
        self.desc = True
        self.timeout = timeout
        self.cmd_args = cmd_args
        self.cwd = cwd
        self.compiler_version = self.get_compiler_version(compiler_bin)

    def compile(self, source):
        from_file = isinstance(source, Path)
        source_prefix = source.stem if from_file else 'stdin'

        if from_file:
            source_uri = source.absolute().as_uri()
        else:
            source_uri = 'stdin'

        # Assemble compiler command
        compiler_cmd = self.__assemble_compiler_cmd(source, from_file)

        # Execute compiler
        res = subprocess.run(compiler_cmd, 
                stdout=subprocess.PIPE, 
                input=None if from_file else source.encode('utf-8'),
                timeout=self.timeout,
                cwd=self.cwd
            ).stdout

        # If compiling on win32, the outputs will be CRLF seperated.
        # We replace CRLF with LF, to make SYNTAX_ERR_REG、SEMANTIC_ERR_REG、IMPORT_ERR_REG work.
        res = res.replace(b'\r\n', b'\n').decode('utf-8')

        # Check compiler output for errors and raise exception if needed.
        self.check_for_errors(res)

        # Collect warnings from compiler output.
        warnings = self.get_warnings(res)

        compiler_result_params = dict()
        out_files = dict()

        if self.ast or self.desc:
            out_file_ast = self.out_dir / '{}_ast.json'.format(source_prefix)
            out_files['ast'] = out_file_ast
            ast_obj = self.load_json(out_file_ast)
            ast_res = self.__collect_results_ast(ast_obj, source_uri)
            compiler_result_params.update(ast_res)
            compiler_result_params['source_file'] = source_uri

        if self.asm or self.desc:
            out_file_asm = self.out_dir / '{}_asm.json'.format(source_prefix)
            out_files['asm'] = out_file_asm
            asm_obj = self.load_json(out_file_asm)
            compiler_result_params['compiler_out_asm'] = asm_obj
            asm_res = self.__collect_results_asm(asm_obj, source)
            compiler_result_params.update(asm_res)

        compiler_result_params['compiler_version'] = self.compiler_version
        compiler_result_params['source_md5'] = self.get_source_md5(source)
        compiler_res = CompilerResult(**compiler_result_params)

        if self.desc:
            out_file_desc = self.out_dir / '{}_desc.json'.format(source_prefix)
            out_files['desc'] = out_file_desc

            desc_res = compiler_res.to_desc(source_map=self.debug)

            with open(out_file_desc, 'w', encoding='utf-8') as f:
                json.dump(desc_res, f, indent=4)

        # TODO: Clean up out files.
        return CompilerResult(**compiler_result_params)

    def __assemble_compiler_cmd(self, source, from_file):
        cmd_buff = [self.compiler_bin, 'compile']

        major_release_ver, minor_release_ver, patch_release_ver = self.__get_compiler_semantic_version_parts()

        if self.asm:
            cmd_buff.append('--asm')
        if self.hex_out:
            cmd_buff.append('--hex')
        if self.ast or self.desc:
            cmd_buff.append('--ast')
        if self.debug:
            cmd_buff.append('--debug')
        if self.stack:
            if major_release_ver >= 1:
                if minor_release_ver >= 1 or patch_release_ver >= 3:
                    cmd_buff.append('--stack')
                    
        if self.optimize:
            cmd_buff.append('--optimize')
        cmd_buff.append('-r')
        cmd_buff.append('-o')
        cmd_buff.append('{}'.format(str(self.out_dir.absolute())))
        if self.cmd_args:
            cmd_buff.append(self.cmd_args)
        if from_file:
            cmd_buff.append(str(source))
        return cmd_buff


    def __get_compiler_semantic_version_parts(self):
        major_release_ver = int(self.compiler_version.split('.')[0])
        minor_release_ver = int(self.compiler_version.split('.')[1])
        patch_release_ver = int(self.compiler_version.split('.')[2][0])
        return (major_release_ver, minor_release_ver, patch_release_ver)


    def __collect_results_ast(self, ast_obj, source_uri):
        res = dict()
        # Change source file paths to URIs
        self.ast_filepaths_to_uris(ast_obj)
        ast_root = ast_obj[source_uri]
        static_int_consts = self.ast_get_static_const_int_declarations(ast_obj)
        aliases = self.ast_get_aliases(ast_obj)
        res['alias'] = aliases
        res['ast'] = ast_root
        abi_declaration = self.ast_get_abi_declaration(ast_root, aliases, static_int_consts)
        res['abi'] = abi_declaration['abi']
        del ast_obj[source_uri]
        res['dep_ast'] = ast_obj
        res['contract'] = abi_declaration['contract']
        res['structs'] = self.ast_get_struct_declarations(ast_root, ast_obj)
        return res

    def __collect_results_asm(self, asm_obj, source):
        res = dict()
        sources = asm_obj['sources']
        sources_fullpath = self.get_sources_fullpath(sources)

        asm_items = []
        for output in asm_obj['output']:
            if not self.debug:
                asm_items.append({ 'opcode': output['opcode'] })
                asm_items.append({ 'hex': output['hex'] })
                continue
            
            match = re.match(SOURCE_REG, output['src'])
            if match:
                file_idx = int(match.group('fileIndex'))

                debug_tag = None
                tag_str = match.group('tagStr')
                if tag_str:
                    if re.search(r'\w+\.\w+:0', tag_str):
                        debug_tag = DebugModeTag.FUNC_START
                    if re.search(r'\w+\.\w+:1', tag_str):
                        debug_tag = DebugModeTag.FUNC_END
                    if re.search(r'loop:0', tag_str):
                        debug_tag = DebugModeTag.LOOP_START

                pos = None
                if len(sources) > file_idx:
                    pos = {
                        'file': sources_fullpath[file_idx],
                        'line': int(match.group('line')),
                        'endLine': int(match.group('endLine')),
                        'column': int(match.group('col')),
                        'endColumn': int(match.group('endCol'))
                        }
                
                asm_items.append({
                    'opcode': output['opcode'],
                    'hex': output['hex'],
                    'stack': output['stack'],
                    'pos': pos,
                    'debugTag': debug_tag
                    })

        res['asm'] = asm_items    

        auto_typed_vars = []
        if self.debug:
            for item in asm_obj['autoTypedVars']:
                match = re.match(SOURCE_REG, item['src'])
                if match:
                    file_idx = int(match.group('fileIndex'))    
                    pos = None
                    if len(sources) > file_idx:
                        s = sources[file_idx] 
                        if s != 'stdin' and s != 'std':
                            pos_file = str(Path(s).absolute())
                        else:
                            pos_file = 'std'
                        pos = {
                            'file': pos_file,
                            'line': int(match.group('line')),
                            'endLine': int(match.group('endLine')),
                            'column': int(match.group('col')),
                            'endColumn': int(match.group('endCol'))
                            }
                    auto_typed_vars.append({
                        'name': item['name'],
                        'type': item['type'],
                        'pos': pos
                        })
        res['auto_typed_vars'] = auto_typed_vars

        return res

    @staticmethod
    def get_compiler_version(compiler_bin):
        res = subprocess.run([compiler_bin, 'version'], stdout=subprocess.PIPE).stdout
        return res.decode(encoding='utf-8').split()[1]

    @staticmethod
    def get_source_md5(source):
        if isinstance(source, Path):
            with open(source, 'r', encoding='utf-8') as f:
                source = f.read()
        return hashlib.md5(source.encode(encoding='utf-8')).hexdigest()

    @staticmethod
    def get_sources_fullpath(sources):
        res = []
        for source in sources:
            if source != 'stdin' and source != 'std':
                res.append(str(Path(source).absolute()))
            else:
                res.append('std')
        return res

    @staticmethod
    def get_asm_as_string(asm_objs):
        res_buff = []
        for item in asm_objs:
           res_buff.append(item['opcode']) 
        return ' '.join(res_buff)

    @staticmethod
    def get_hex_script(asm_objs):
        res_buff = []
        for item in asm_objs:
           res_buff.append(item['hex']) 
        return ''.join(res_buff)

    @staticmethod
    def get_full_source_path(rel_path, base_dir, cur_file_name):
        if rel_path.endswith('stdin'):
            return str(Path(base_dir, cur_file_name))
        if rel_path == 'std':
            return 'std'
        return str(Path(base_dir, rel_path))

    @staticmethod
    def ast_filepaths_to_uris(asts):
        keys = list(asts.keys())
        for key in keys:
            if not key == 'stdin':
                source_uri = Path(key).absolute().as_uri()
                asts[source_uri] = asts.pop(key)

    @staticmethod
    def load_json(file_json):
        with open(file_json, 'r', encoding='utf-8') as f:
            obj = json.load(f)
        return obj

    @staticmethod
    def ast_get_aliases(asts):
        res = []
        for ast in asts.values():
            for alias in ast['alias']:
                res.append({
                    'name': alias['alias'],
                    'type': alias['type']
                    })
        return res

    @staticmethod
    def ast_get_static_const_int_declarations(asts):
        res = dict()
        for ast in asts.values():
            contracts = ast['contracts']
            for contract in contracts:
                contract_name = contract['name']
                for static in contract['statics']:
                    if not static['const'] or static['expr']['nodeType'] != 'IntLiteral':
                        continue
                    name = '{}.{}'.format(contract_name, static['name'])
                    value = static['expr']['value']
                    res[name] = int(value)
        return res

    @staticmethod
    def ast_get_abi_declaration(ast, aliases, static_int_consts):
        main_contract = ast['contracts'][-1]
        if not main_contract:
            return { 'contract': '', 'abi': [] }

        main_contract_name = main_contract['name']
        interfaces = CompilerWrapper.get_public_function_declarations(main_contract)
        constructor = CompilerWrapper.get_constructor_declaration(main_contract)
        interfaces.append(constructor)

        for interface in interfaces:
            for param in interface['params']:
                p_type = CompilerWrapper.resolve_abi_param_type(
                            main_contract_name,
                            param['type'], 
                            aliases,
                            static_int_consts
                            )
                param['type'] = p_type

        return { 'contract': main_contract_name, 'abi': interfaces }

    @staticmethod
    def ast_get_struct_declarations(ast_root, dependency_asts):
        res = []
        all_asts = [ast_root]
        for key in dependency_asts.keys():
            all_asts.append(dependency_asts[key])

        for ast in all_asts:
            for struct in ast['structs']:
                name = struct['name']
                params = []
                for field in struct['fields']:
                    p_name = field['name']
                    p_type = field['type']
                    params.append({ 'name': p_name, 'type': p_type })
                res.append({ 'name': name, 'params': params })
        return res

    @staticmethod
    def get_public_function_declarations(contract):
        res = []
        pub_index = 0
        functions = contract['functions']
        for function in functions:
            if function['visibility'] == 'Public':
               abi_type = 'function'
               name = function['name'] 
               if function['nodeType'] == 'Constructor':
                   index = None
               else:
                   index = pub_index
                   pub_index += 1
               params = []
               for param in function['params']:
                   p_name = param['name']
                   p_type = param['type']
                   params.append({ 'name': p_name, 'type': p_type })

               abi_entity = {
                    'type': abi_type,
                    'name': name,
                    'index': index,
                    'params': params
                    }
               res.append(abi_entity)
        return res

    @staticmethod
    def get_constructor_declaration(contract):
        constructor = contract['constructor']   # Explicit constructor
        properties = contract['properties']     # Implicit constructor
        params = []
        if constructor:
            for param in constructor['params']:
                p_name = param['name']
                p_type = param['type']
                params.append({ 'name': p_name, 'type': p_type })
        elif properties:
            for prop in properties:
                p_name = prop['name'].replace('this.', '')
                p_type = prop['type']
                params.append({ 'name': p_name, 'type': p_type })
        return {'type': 'constructor', 'params': params}

    @staticmethod
    def resolve_abi_param_type(contract_name, type_str, aliases, static_int_consts):
        if utils.is_array_type(type_str):
            resolved_type = CompilerWrapper.resolve_array_type_w_const_int(contract_name, 
                    type_str, static_int_consts)
        else:
            resolved_type = utils.resolve_type(type_str, aliases)

        if utils.is_struct_type(resolved_type):
            return utils.get_struct_name_by_type(resolved_type)
        elif utils.is_array_type(resolved_type):
            elem_type_name, array_sizes = utils.factorize_array_type_str(resolved_type)

            if utils.is_struct_type(elem_type_name):
                elem_type_name = utils.get_struct_name_by_type(resolved_type)

            return utils.to_literal_array_type(elem_type_name, array_sizes)

        return resolved_type

    @staticmethod
    def resolve_array_type_w_const_int(contract_name, type_str, static_int_consts):
        # Resolves array declaration string with static constants as sizes.
        # e.g. 'int[N][2]' -> 'int[5][2]'
        elem_type_name, array_sizes = utils.factorize_array_type_str(type_str)

        # Resolve all constants to integers.
        sizes = []
        for size_str in array_sizes:
            if size_str.isdigit():
                sizes.append(int(size_str))
            else:
                if size_str.find('.') > 0:
                    sizes.append(static_int_consts[size_str])
                else:
                    sizes.append(static_int_consts['{}.{}'.format(contract_name, size_str)])

        return utils.to_literal_array_type(elem_type_name, sizes)

    @staticmethod
    def check_for_errors(compiler_output):
        # TODO: missing output folder: 
        # "scryptc: /tmp/scryptlib/stdin_asm.json: openFile: does not exist (No such file or directory)"
        if compiler_output.startswith('Error:'):
            match = re.search(INTERNAL_ERR_REG, compiler_output)
            if match:
                raise InternalError('Compiler internal error: {}'.format(match.group('message')))

            syntax_err_entries = []
            for match in re.finditer(SYNTAX_ERR_REG, compiler_output):
                file_path = match.group('filePath')
                got = match.group('unexpected')
                expected = match.group('expecting')
                line = int(match.group('line'))
                col = int(match.group('column'))
                message = match.group('message')
                message_full = match.string

                error_entry = SyntaxErrorEntry(message, message_full, got, expected, (line, col), file_path)
                syntax_err_entries.append(error_entry)

            if len(syntax_err_entries) > 0:
                raise SyntaxError(syntax_err_entries)

            semantic_err_entries = []
            for match in re.finditer(SEMANTIC_ERR_REG, compiler_output):
                file_path = match.group('filePath')
                line = int(match.group('line'))
                col = int(match.group('column'))
                line1 = int(match.group('line1'))
                col1 = int(match.group('column1'))
                position_range = [(line, col), (line1, col1)]
                message = match.group('message')
                message_sub_reg = r'Symbol `(?P<varName>\w+)` already defined at (?P<fileIndex>[^\s]+)' \
                        r':(?P<line>\d+):(?P<column>\d+):(?P<line1>\d+):(?P<column1>\d+)'
                message = re.sub(message_sub_reg, 'Symbol `$1` already defined at $3:$4:$5:$6', message)
                message_full = match.string

                error_entry = SemanticErrorEntry(message, message_full, position_range, file_path)
                semantic_err_entries.append(error_entry)

            if len(semantic_err_entries) > 0:
                raise SemanticError(semantic_err_entries)

            raise Exception(compiler_output)

    @staticmethod
    def get_warnings(compiler_output):
        warnings = []
        for match in  re.finditer(WARNING_REG, compiler_output):
            file_path = match.group('filePath')

            line = int(match.group('line'))
            col = int(match.group('column'))
            line1 = int(match.group('line1'))
            col1 = int(match.group('column1'))

            message = match.group('message')
            message_sub_reg = r'Variable `(?<varName>\w+)` shadows existing binding at ' \
                    r'(?<fileIndex>[^\s]+):(?<line>\d+):(?<column>\d+):(?<line1>\d+):(?<column1>\d+)'
            message = re.sub(message_sub_reg, 'Variable `$1` shadows existing binding at $3:$4:$5:$6', message)

            warnings.append((file_path, [(line, col), (line1,col1)], message))
        return warnings


