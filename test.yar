rule test_1 {
  condition: false
}

rule test_2 {
  strings:
     $ = "foobarbaz"
  condition:
     all of them
}

rule test_3 {
  strings:
     $ = "foobarbazquux"
  condition:
     all of them
}
