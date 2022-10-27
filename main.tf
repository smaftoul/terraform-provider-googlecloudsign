terraform {
  required_providers {
    googlecdnsign = {
      source = "smaftoul/googlecdnsign"
    }
  }
}

data "googlecdnsign_cookie" "default" {
  key = "YmxhCg==" # "bla" in base64
  key_name = "bla"
  expiration = 1666873935
  prefix = "/"
  domain = "example.com"
}

output "cookie" {
  value = data.googlecdnsign_cookie.default.url
}
