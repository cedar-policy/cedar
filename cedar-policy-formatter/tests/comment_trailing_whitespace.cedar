// Tests that trailing spaces are correctly removed at the end of comment lines.

// ___WARNING___ Some editors will automaticaly trim trailing whitespace, but
// this file expliciclty tests formatter behavior in this case. When making
// changes to this file check that the comments still have trailing whitespace.

// There is a space at the end of this line 
permit (principal, action, resource);

// No space here
// But there is one here 
permit (principal, action, resource);

// No space here
 // Leading space before this comment
// A tab character here:	
permit (principal, action, resource);

permit (principal, // Trailing comment Space 
// Leading comment Space  
// Leading comment Space   
// Leading comment Space    
action, resource);

// end of file comment with space 
// on these lines 

// trailing whitespace on the last line is ignored by insta, so we test that 
// case as part of `test_add_trailing_newline` in `fmt.rs` 
