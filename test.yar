rule test_1 {
  condition: false
}

rule test_2 {
  strings:
     $ = "foobarbaz"
  condition:
     all of them
}
