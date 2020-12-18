from binaryninja import binaryview
from binaryninja import MediumLevelILOperation
from binaryninja import PluginCommand
from binaryninja import function

class Issue():
    def __init__(self, addr, string_literal, n, hlil_instr):
        self.addr = addr
        self.string_literal = string_literal
        self.n = n
        self.hlil_instr = hlil_instr
    
    def as_markdown_row(self):
        return " ".join([
            f"| [{hex(self.addr)}](binaryninja://?expr={hex(self.addr)})", 
            f"| *{self.string_literal[:self.n]}* `{self.string_literal[self.n:]}` ", 
            #f"| {self.string_literal} "
            f"| {self.n} ", 
            f"| {len(self.string_literal)} ", 
            f"| {len(self.string_literal) - self.n} ", 
            f"| `{self.hlil_instr}` |",
        ])


class Cstrfinder():

    def __init__(self, bv):
        self.call_targets = [
                "strncmp", "strnicmp", "strncat", "stpncpy", "strncpy", "strncasecmp","memcmp", 
                "memcpy", "memmove", "mempcpy", "wmemcpy", "wmemmove", "wmempcpy", "bcopy", "bcmp",
            ]
        self.bv = bv
        self.issues = list()
        self.check_calls()
        self.report()

    def check_calls(self):
        for func in self.call_targets:
            try:
                for ref in self.bv.get_code_refs(self.bv.symbols[func][0].address):
                    self.check_call(ref.address)
            except KeyError:
                print(f"[-] No reference for {func} found.")


    def check_call(self, addr):
        func = self.bv.get_functions_containing(addr)[0]
        mlil =  func.get_low_level_il_at(addr).medium_level_il
        params = mlil.params
        s1 = params[0]
        s2 = params[1]
        n = params[2]

        # check if s1 or s2 are constant
        try:
            const_str = self.bv.get_string_at(s1.constant)
            if const_str.length > n.constant:
                self.issues.append( Issue(addr, const_str.value, n.constant, str(mlil.hlil)) )
        except AttributeError:
            pass
        
        try:
            const_str = self.bv.get_string_at(s2.constant)
            if const_str.length > n.constant:
                self.issues.append( Issue(addr, const_str.value, n.constant, str(mlil.hlil)) )
        except AttributeError:
            pass
            
    def report(self):
        md_report = [
            "| Address | String | constant n | Strlen | difference | Pseudo Code |",
            "| --- | --- | --- | --- | --- | --- |",
            ]
        for issue in self.issues:
            md_report.append(issue.as_markdown_row())
        report = "\n".join(md_report)
        self.bv.show_markdown_report("cstrfinder", report)

PluginCommand.register("cstrfinder", "cstrfinder", Cstrfinder)