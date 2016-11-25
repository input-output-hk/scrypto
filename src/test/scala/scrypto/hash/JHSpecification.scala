package scrypto.hash

import scrypto.utils.BytesHex.hex2bytes

class JHSpecification extends HashTest {

  hashCheck(JH256,
    Map(
      emptyBytes -> "46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434",
      hex2bytes("cc") -> "7b1191f13a2667830142541bfc5918543d2a434c7692e70c3e5e9bbdddb7f581"
    )
  )

  hashCheck(JH512,
    Map(
      emptyBytes -> "90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f",
      hex2bytes("cc") -> "277c93806945992a7f10102f28471af2783fe32003b3f63320810e74f1bc233bf8669ab4b922db9ef13fcdcd4d31193b731eedde98fc87c129c04a4a1071f66f"
    )
  )

}
