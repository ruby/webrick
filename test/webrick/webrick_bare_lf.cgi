#!ruby

body = "test for bare LF in cgi header"

print "Content-Type: text/plain\n"
print "Content-Length: #{body.size}\n"
print "\n"
print body
