;; Detect Express route definitions: app.get("/path", handler), router.post(...), etc.
;; Matches member_expression with HTTP methods (get, post, put, patch, delete, use, all).
;; NOTE: #match? predicates are not enforced by the Python bindings;
;; filtering by method name is done in Python code.

(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  arguments: (arguments) @args) @call
