from binaryninja import binaryview
from binaryninja import MediumLevelILOperation
from binaryninja import PluginCommand
from binaryninja import function
from html import escape

class Issue():
    def __init__(self, addr, string_literal, n, hlil_instr):
        self.addr = addr
        self.string_literal = string_literal
        self.n = n
        self.hlil_instr = hlil_instr
        self.checked  = string_literal[:n]
        self.un_checked = string_literal[n:]
    
    def as_markdown_row(self):
        return " ".join([
            f"| [{hex(self.addr)}](binaryninja://?expr={hex(self.addr)})", 
            f"| *{self.checked}* `{self.un_checked}` ", 
            #f"| {self.string_literal} "
            f"| {self.n} ", 
            f"| {len(self.string_literal)} ", 
            f"| {len(self.string_literal) - self.n} ", 
            f"| `{self.hlil_instr}` |",
        ])
    
    def as_html_row(self):
        return " ".join([
            "<tr>",
            f"<td> <a href='binaryninja://?expr={hex(self.addr)}'>{hex(self.addr)}</a> </td>",
            f"<td> <font color=lightgreen>{escape(self.checked)}</font><font color=red>{escape(self.un_checked)}</font> </td>",
            f"<td> {self.n} </td>",
            f"<td> {len(self.string_literal)} </td>",
            f"<td> {len(self.string_literal) - self.n} </td>",
            f"<td><code>{escape(self.hlil_instr)}</code></td>",
            "</tr>",
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
        #self.show_md_report()
        self.show_html_report()

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
            
    def show_md_report(self):
        md_report = [
            "| Address | String | constant n | Strlen | difference | Pseudo Code |",
            "| --- | --- | --- | --- | --- | --- |",
            ]
        for issue in self.issues:
            md_report.append(issue.as_markdown_row())
        report = "\n".join(md_report)
        self.bv.show_markdown_report("cstrfinder", report)
    
    def show_html_report(self):
        html_report = [
            "<html> <head> <title> cstrnfinder </title> </head> <body> ",
            "<table style='width:100%'>"
            "<tr>",
            "<td>Address</td>",
            "<td>String</td>",
            "<td>Constant n</td>",
            "<td>Strlen</td>",
            "<td>Difference</td>",
            "<td>Pseudo Code</td>",
            "</tr>",
        ]
        for issue in self.issues:
            html_report.append(issue.as_html_row())
        html_report.append("</table></body></html>")
        report = "\n".join(html_report)
        self.bv.show_html_report("cstrfinder", report)


PluginCommand.register("cstrfinder", "cstrfinder", Cstrfinder)