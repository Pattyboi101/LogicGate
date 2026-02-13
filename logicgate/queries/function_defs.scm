;; Detect function declarations: function foo() {}
;; and arrow function assignments: const foo = () => {}

;; Standard function declarations
(function_declaration
  name: (identifier) @name) @func

;; Arrow function assigned to const/let/var
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (arrow_function) @arrow)) @decl
