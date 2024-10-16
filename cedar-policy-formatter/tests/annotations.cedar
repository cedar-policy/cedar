@id("foo")
permit (principal, action, resource);

@id("
foo

bar
")
permit (principal, action, resource);

@shadow_mode
permit (principal, action, resource);

@shadow_mode("")
permit (principal, action, resource);

@shadow_mode // shadow mode is on
permit (principal, action, resource);

@shadow_mode("") // shadow mode is also on
permit (principal, action, resource);

@foo@bar@baz("buz") permit(principal, action, resource);

// foo
@foo@bar
// baz buz
@baz("buz")
// also biz
@biz
permit (principal, action, resource);

@//1
//2
shadow_mode//3
//4
permit (principal, action, resource);

@//5
//6
shadow_mode//7
//8
(//9
//10
""//11
//12
)//13
//14
permit (principal, action, resource);
