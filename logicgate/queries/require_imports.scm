;; Detect CommonJS require: const foo = require("./bar")

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (call_expression
      function: (identifier) @req_fn
      arguments: (arguments
        (string) @source)))) @decl
