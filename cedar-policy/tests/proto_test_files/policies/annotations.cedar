@id("annotated-policy")
@advice("this is advice with \"quotes\" and unicode: ñ café")
@reason("a reason")
permit(
    principal,
    action,
    resource
);
