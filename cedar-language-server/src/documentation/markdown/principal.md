# Principal

The principal element in a Cedar policy represents a user, service, or other identity
that can make a request to perform an action on a resource in your application. If the
principal making the request matches the principal defined in this policy statement,
then this element matches.

The principal element must be present. If you specify only principal without an expression
that constrains its scope, then the policy applies to any principal.
