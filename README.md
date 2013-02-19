sge-sshd-control
================

Fork of sge-sshd-control originally by Andreas Haupt <andreas.haupt@desy.de>.

Originally downloaded from
http://www-zeuthen.desy.de/~ahaupt/downloads/sge-sshd-control-1.2-1.src.rpm

I modified the source to get the PPID directly rather than from invoking "ps". That code was taken from user "Hko" at
http://www.linuxquestions.org/questions/programming-9/function-for-getting-pid-of-any-process-276839

I also converted the Perl-based rshd-wrapper into sshd-wrapper written in
Bourne shell.
