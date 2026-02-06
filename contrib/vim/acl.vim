" ACL language syntax highlighting
" Filetype: acl
" Save as: ~/.config/nvim/syntax/acl.vim

" Clear previous highlighting
syn clear

" --------------------
" Comments (C-style single-line)
" --------------------
syn match aclComment "//.*$" contains=@Spell
syn match aclComment "#.*$" contains=@Spell
hi def link aclComment Comment

" --------------------
" Keywords
" --------------------
syn keyword aclKeyword backend route policy when require action allow deny redirect
hi def link aclKeyword Keyword

" --------------------
" Comparators / operators
" --------------------
syn match aclComparator "==\|!=\|=~\|<\|<=\|>\|>=\|in\|not\s\+in"
hi def link aclComparator Operator

" --------------------
" Boolean literals
" --------------------
syn keyword aclBoolean true false
hi def link aclBoolean Boolean

" --------------------
" Identifiers (variable names, backends, routes, user/group/etc)
" --------------------
syn match aclIdentifier "\<[A-Za-z_][A-Za-z0-9_-]*\>"
hi def link aclIdentifier Identifier

" --------------------
" Strings
" --------------------
syn region aclString start=+"+ skip=+\\\\\|\\"+ end=+"+
hi def link aclString String

" --------------------
" Numbers
" --------------------
syn match aclNumber "\<\d\+\>"
hi def link aclNumber Number

" --------------------
" Highlight inline actions
" --------------------
syn match aclAction "\<allow\>\|\<deny\>\|\<redirect\>"
hi def link aclAction Statement

" --------------------
" Define the filetype
" --------------------
let b:current_syntax = "acl"
