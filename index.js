'use strict';
const _ = require("lodash");
const fs = require("fs");
const path = require("path");
const exec = require('child_process').exec;
const sshpk = require('sshpk');

const certDirectoryPath = './cert';

function getCertFileList () {
  return new Promise(function(resolve, reject) {
    fs.readdir(certDirectoryPath, function(err, fileList) {
      if(err) return reject(err);
      resolve(fileList);
    });
  })
}

function getFileInfo (fileName) {
  const filePath = path.join(certDirectoryPath, fileName);
  const extName = path.extname(filePath);
  const context = fs.readFileSync(filePath, 'utf-8');

  let info_d = {
    name: fileName,
    path: path.join(__dirname, certDirectoryPath, fileName),
    extType : undefined, // pem, der, p12
    private: false, //private key?
    issuer: undefined,
    subjects: []
  };

  if (context.indexOf('-----BEGIN ENCRYPTED PRIVATE KEY-----') >= 0) {
    info_d.extType = 'pem';
    info_d.private = true;
  } else if (context.indexOf('-----BEGIN CERTIFICATE-----') >= 0) {
    info_d.extType = 'pem';
  } else if (extName === '.priv') {
    info_d.private = true;
  } else if (extName === '.p12') {
    info_d.extType = 'p12';
  } else if (extName === '.pem') {
    info_d.extType = 'pem';
  } else if (extName === '.der') {
    info_d.extType = 'der';
  } else if (extName === '.cer' && info_d.extType === undefined) {
    info_d.extType = 'der';
  }
  if(info_d.private === false && ['der', 'pem'].findIndex(function (e) {return e === info_d.extType}) >= 0) {
    var certificate = sshpk.parseCertificate(info_d.extType === 'der' ? fs.readFileSync(filePath, 'binary') : context, info_d.extType === 'der' ? 'x509' : 'pem');
    info_d.issuer = `${_.get(certificate, ['issuer', 'uid'], '')}${_.get(certificate, ['issuer', 'cn'], '')}${_.get(certificate, ['issuer', 'type'], '')}${_.get(certificate, ['issuer', 'hostname'], '')}`;
    certificate.subjects.forEach(function (subject) {
      info_d.subjects.push(`${_.get(subject, ['uid'], '')}${_.get(subject, ['cn'], '')}${_.get(subject, ['type'], '')}${_.get(subject, ['hostname'], '')}`);
    })
  }

  return info_d;
}

function divisionCertificateClass(fileInfoList) {
  return new Promise(function(resolve, reject) {
    var rootCa, intermediates = [], endEntity, endEntityKey;
    let certInfoList = [];

    fileInfoList.forEach(function(certInfo) {
      if (certInfo.private) {
        endEntityKey = certInfo;
      } else if (certInfo.extType === 'p12') {
        endEntity = certInfo;
      } else if (certInfo.issuer && certInfo.subjects.length > 0) {
         if(certInfoList.length === 0) {
           certInfoList.push(certInfo);
         } else {
           const issuerIndex = certInfoList.findIndex(function(value) { return value.subjects[0] === certInfo.issuer });
           if(issuerIndex >= 0) {
             certInfoList.splice(issuerIndex + 1, 0, certInfo);
             return;
           }
           const subjectIndex = certInfoList.findIndex(function(value) { return value.issuer === certInfo.subjects[0] });
           if(subjectIndex >= 0) {
             certInfoList.splice(subjectIndex, 0, certInfo);
           }
         }
      }
    })
    if (certInfoList.length > 0) {
      if (!rootCa) rootCa = certInfoList.shift();
      if (!endEntity) endEntity = certInfoList.pop();
      intermediates.push(...certInfoList);
    }
    resolve({
      rootCa: rootCa,
      intermediates: intermediates,
      endEntity: endEntity,
      endEntityKey: endEntityKey
    });
  })
}

~function main () {
  let tempFilesInfo = [];
  getCertFileList()
    .then(function(fileList) {
      for(let i=0, l=fileList.length; i < l; i++) {
        const fileName = fileList[i];
        const fileInfo = getFileInfo(fileName);

        if(fileInfo) {
          tempFilesInfo.push(fileInfo);
        }
      }
      return divisionCertificateClass(tempFilesInfo);
    })
    .then(function (result) {
      console.log(result);
    })
    .catch(function (err) {
      console.log(err);
    })
}()