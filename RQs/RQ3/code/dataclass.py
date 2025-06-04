from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Dict, NamedTuple, Any 


RelatedMethod = NamedTuple( # function
    "RelatedMethod",
    [("filename", str), ("method_name", str), ("raw_code", str)],
)

CallerMethod = NamedTuple( # caller
    "CallerMethod",
    [("filename", str), ("method_name", str), ("raw_code", str), ("call_code", str)],
)

ValueTrace = NamedTuple(
    "ValueTrace",
    [
        ("value_info", str),                   
        ("value_trace_details", List[Dict[str, Any]]),
        ("struct_var", str),               
        ("struct_type", str),              
        ("struct_definition", str),            
    ],
)

Code_Snippet = NamedTuple( # code
    "Code_Snippet",
    [
        ("filename", str),
        ("raw_code", str),
        ("start_line", int),
        ("end_line", int),
    ],
)

QueryContext = NamedTuple( # query_info
    "QueryContext", # Renamed from "Raw_Query - Result" for clarity
    [
        ("query", str),
        ("result", str),
    ],
)

VulnMethod = NamedTuple( # function before or after
    "VulnMethod",
    [("filename", str), ("method_name", str), ("raw_code", str), ("patch_start", int), ("patch_count", int)], 
)


@dataclass
class VulnObj:
    code: str
    cwe: str
    is_vulnerable: bool


@dataclass
class Example:
    code: str
    cwe: str
    is_vulnerable: bool
    explanation: str


@dataclass
class VulnPair: # This structure might become less relevant with the new context type
    cwe: List[str]
    vuln: str
    patched: str
    name: str
    method: List[str]
    context: str


@dataclass
class VulAgentContext:
    relatedMethods: List[RelatedMethod]
    callerMethods: List[CallerMethod]
    codeSnippets: List[Code_Snippet]
    valueTraces: List[ValueTrace]
    queryContexts: List[QueryContext]

    def __str__(self) -> str:
        parts = []

        # --- Related Methods ---
        if self.relatedMethods:
            parts.append("### Related Methods ###")
            parts.append("Description: Code of methods identified as potentially related to the Code.")
            parts.append("") 
            methods_by_file: Dict[str, List[RelatedMethod]] = {}
            for method in self.relatedMethods:
                methods_by_file.setdefault(method.filename, []).append(method)

            for filename, methods in methods_by_file.items():
                parts.append(f"File: {filename}")
                for method in methods:
                    parts.append(f"Method: {method.method_name}")
                    parts.append("```")
                    parts.append(method.raw_code)
                    parts.append("```")
                parts.append("") 

        # --- Caller Methods ---
        if self.callerMethods:
            parts.append("### Caller Methods ###")
            parts.append("Description: Code of methods that call into the Code or Related Methods, showing the call site within the caller.")
            parts.append("") 

            for i, method in enumerate(self.callerMethods):
                parts.append(f"- Caller Method {i+1}:")
                parts.append(f"  File: {method.filename}")
                parts.append(f"  Method Name: {method.method_name}")
                parts.append(f"  Call Site: `{method.call_code}`")
                parts.append("  Caller Code:")
                parts.append("```") 
                parts.append(method.raw_code)
                parts.append("```")
                parts.append("") 


        # --- Code Snippets ---
        if self.codeSnippets:
             parts.append("### Code Snippets ###")
             parts.append("Description: Additional relevant code snippets from various locations, providing broader context.")
             parts.append("")

             for i, snippet in enumerate(self.codeSnippets):
                  parts.append(f"- Snippet {i+1}:")
                  parts.append(f"  File: {snippet.filename}, Lines: {snippet.start_line}-{snippet.end_line}")
                  parts.append("```") 
                  parts.append(snippet.raw_code)
                  parts.append("```")
                  parts.append("") 

        # --- Value Traces --
        if self.valueTraces:
            parts.append("### Value Trace Context ###")
            parts.append("Description: Context about variables/values, their types, definitions, and usage traces.")
            parts.append("") 

            structured_traces = {}
            unstructured_traces = []

            for trace in self.valueTraces:
                if trace.struct_type and trace.struct_definition:
                    if trace.struct_type not in structured_traces:
                        structured_traces[trace.struct_type] = {
                            "definition": trace.struct_definition, 
                            "traces": []
                        }           
                    structured_traces[trace.struct_type]["traces"].append(trace)
                else:
                    unstructured_traces.append(trace)

            
            if structured_traces:
                parts.append("--- Traces Grouped by Structure Type ---")
                parts.append("") 

                for struct_type, data in structured_traces.items():
                    parts.append(f"Structure Type: {struct_type}")
                    parts.append("Definition:")
                    parts.append("```") 
                    parts.append(data['definition'])
                    parts.append("```")

                    parts.append("Related Value Traces:")

            
                    for i, trace in enumerate(data['traces']):
                        parts.append(f"- Trace {i+1} related to {struct_type}:")
                        parts.append(f"  Value Info: {trace.value_info}")
                
                        if trace.struct_var:
                             parts.append(f"  Variable: {trace.struct_var}")

            
                        if trace.value_trace_details:
                            parts.append("  Trace Steps:")
                            for step in trace.value_trace_details:
        
                                parts.append(f"  - Function: {step.get('func_name', 'N/A')}, Line: {step.get('line', '?')}, Code: `{step.get('full_code', 'N/A')}`")
        

                    parts.append("") 

            if unstructured_traces:
                parts.append("--- Other Value Traces (Missing Type/Definition) ---")
                parts.append("") 
                for i, trace in enumerate(unstructured_traces):
                     parts.append(f"- Trace {i+1} (Unstructured):") 
                     parts.append(f"  Value Info: {trace.value_info}")
                     if trace.struct_var:
                         parts.append(f"  Variable: {trace.struct_var}") 

                     if trace.value_trace_details:
                        parts.append("  Trace Steps:")
                        for step in trace.value_trace_details:
                            parts.append(f"  - Function: {step.get('func_name', 'N/A')}, Line: {step.get('line', '?')}, Code: `{step.get('full_code', 'N/A')}`")


                     parts.append("")


        # --- Query Contexts ---
        if self.queryContexts:
            parts.append("### Query Contexts ###")
            parts.append("Description: Pairs of queries performed (e.g., database lookups, specific tool queries) and their results.")
            parts.append("")

            for i, query_item in enumerate(self.queryContexts):
                 parts.append(f"- Query {i+1}: {query_item.query}")
                 parts.append(f"  Result: {query_item.result}")
                 parts.append("") 

        return "\n".join(parts)


@dataclass
class VulnPairWithContext:
    cwe: List[str]
    vuln: List[VulnMethod]
    patched: List[VulnMethod]
    name: str
    context: VulAgentContext 
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    

