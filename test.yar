rule test_1 {
  condition: false
}

rule test_2 {
  strings:
     $ = "foobar"
  condition:
     all of them
}

rule test_3 {
  strings:
     $ = "foobarbazquux"
  condition:
     all of them
}

rule test_4 {
  strings:
     $ = "foobarbazquux"
  condition:
     all of them
}


rule test_5 {
  strings:
     $ = "foobarbazquux"
  condition:
     all of them
}


