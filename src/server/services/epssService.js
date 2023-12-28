const forge = require('node-forge')
const fs = require('fs')
const path = require('path')

module.exports.sign = async function (dataString, keyString) {
  try {

    return true
  } catch (error) {
    console.error('Error executing commands:', error.message)
    return false
  }
}


module.exports.deSign = async function (dataString) {
  try {

    return true
  } catch (error) {
    console.error('Error executing commands:', error.message)
    return false
  }
}



