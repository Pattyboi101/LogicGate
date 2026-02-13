;; Detect function calls: foo(args) and obj.method(args)

;; Direct function calls: foo(args)
(call_expression
  function: (identifier) @fn_name) @call

;; Member function calls: obj.method(args)
(call_expression
  function: (member_expression
    object: (_) @obj
    property: (property_identifier) @method_name)) @member_call
