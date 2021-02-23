"use strict";

var loopback = require("loopback");
var boot = require("loopback-boot");

var app = (module.exports = loopback());
var configLocal = require("./config.local");

const logger = require("../common/logger");

const uuidv3 = require("uuid/v3");

// Create an instance of PassportConfigurator with the app instance
var PassportConfigurator = require("loopback-component-passport")
    .PassportConfigurator;
var passportConfigurator = new PassportConfigurator(app);

// enhance the profile definition to allow for applying regexp based substitution rules to be applied
// to the outcome of e.g. LDAP queries. This can for example be exploited to define the groups
// a user belongs to by scanning the output of the memberOf fields of a user
//
// example of a profile entry in providers.json:
// "accessGroups": ["memberOf", {match-string}, {substitution-string}]
//
// Please note: the match and substitution strings must escape the backslash and
// double quote characters inside providers.json by prepending a backslash

passportConfigurator.buildUserLdapProfile = function(user, options) {
    var profile = {};

    for (var profileAttributeName in options.profileAttributesFromLDAP) {
        var profileAttributeValue =
            options.profileAttributesFromLDAP[profileAttributeName];

        if (profileAttributeValue.constructor === Array) {
            var regex = new RegExp(profileAttributeValue[1], "g");
            // transform array elements to simple group names
            // then filter relevant elements by applying regular expression on element names
            var newList = [];
            var memberOfList = user[profileAttributeValue[0]];
            if (memberOfList instanceof Array) {
                user[profileAttributeValue[0]].map(function(elem) {
                    if (elem.match(regex)) {
                        newList.push(
                            elem.replace(regex, profileAttributeValue[2])
                        );
                    }
                });
            } else if (typeof memberOfList == "string") {
                if (memberOfList.match(regex)) {
                    newList.push(
                        memberOfList.replace(regex, profileAttributeValue[2])
                    );
                }
            }
            profile[profileAttributeName] = newList;
        } else {
            if (profileAttributeValue in user) {
                profile[profileAttributeName] = JSON.parse(
                    JSON.stringify(user[profileAttributeValue])
                );
            } else {
                profile[profileAttributeName] = "";
            }
        }
    }
    // If missing, add profile attributes required by UserIdentity Model
    if (!profile.username) {
        profile.username = [].concat(user["cn"])[0];
    }
    if (!profile.thumbnailPhoto2) {
        if (user.hasOwnProperty("_raw")) {
            let img;
            const userRaw = user._raw;
            if (userRaw.hasOwnProperty("THUMBNAILPHOTO")) {
                img = user._raw.THUMBNAILPHOTO;
            } else if (userRaw.hasOwnProperty("thumbnailPhoto")) {
                img = user._raw.thumbnailPhoto;
            }
            if (img) {
                profile.thumbnailPhoto =
                    "data:image/jpeg;base64," + img.toString("base64");
            } else {
                profile.thumbnailPhoto = "error: no photo found";
            }
        } else {
            profile.thumbnailPhoto = "error: no photo found";
        }
    }
    if (!profile.id) {
        profile.id = user["uid"];
        if (!("uid" in user)) {
            const MY_NAMESPACE = "1b671a64-40d5-491e-99b0-da01ff1f3341";
            const generated_id = uuidv3(user["mail"], MY_NAMESPACE);
            profile.id = generated_id;
        }
    }
    if (!profile.emails) {
        var email = [].concat(user["mail"])[0];
        if (!!email) {
            profile.emails = [
                {
                    value: email
                }
            ];
        }
    }

    if (configLocal.site === "ESS") {
        if (!profile.accessGroups) {
            profile.accessGroups = ["ess", "loki", "odin"];
        }
    }

    console.log("++++++++++ Profile:", profile);
    return profile;
};

if ("queue" in configLocal) {
    var msg = "Queue configured to be ";
    switch (configLocal.queue) {
        case "rabbitmq":
            console.log(msg + "RabbitMQ");
            break;
        case "kafka":
            console.log(msg + "Apache Kafka");
            break;
        default:
            console.log("Queuing system not configured.");
            break;
    }
}

if ("smtpSettings" in configLocal) {
    console.log("Email settings detected");
}

var bodyParser = require("body-parser");
app.start = function() {
    // start the web server
    return app.listen(function() {
        app.emit("started");
        var baseUrl = app.get("url").replace(/\/$/, "");
        console.log("Web server listening at: %s", baseUrl);
        if (app.get("loopback-component-explorer")) {
            var explorerPath = app.get("loopback-component-explorer").mountPath;
            console.log("Browse your REST API at %s%s", baseUrl, explorerPath);
        }
    });
};

// Bootstrap the application, configure models, datasources and middleware.
// Sub-apps like REST API are mounted via boot scripts.
boot(app, __dirname, function(err) {
    if (err) throw err;

    // start the server if `$ node server.js`
    if (require.main === module) app.start();
});

// to support JSON-encoded bodies
app.middleware(
    "parse",
    bodyParser.json({
        limit: "50mb"
    })
);
// to support URL-encoded bodies
app.middleware(
    "parse",
    bodyParser.urlencoded({
        limit: "50mb",
        extended: true
    })
);
// // The access token is only available after boot
app.middleware(
    "auth",
    loopback.token({
        model: app.models.accessToken
    })
);

// Load the provider configurations
var config = {};
try {
    config = require("./providers.json");
} catch (err) {
    console.error(
        "Please configure your passport strategy in `providers.json`."
    );
    process.exit(1);
}

// Initialize passport
passportConfigurator.init();

// Set up related models
passportConfigurator.setupModels({
    userModel: app.models.user,
    userIdentityModel: app.models.userIdentity,
    userCredentialModel: app.models.userCredential
});
// Configure passport strategies for third party auth providers
for (var s in config) {
    var c = config[s];
    c.session = c.session !== false;
    if (c.provider === "ldap") {
        c["failureErrorCallback"] = err => logger.logError(err.message, {});
    }
    passportConfigurator.configureProvider(s, c);
}

/*********************************************/
/***********     用户管理接口     *************/
/*********************************************/

const User = app.models.User;
const Role = app.models.Role;
const RoleMapping = app.models.RoleMapping;
RoleMapping.settings.strictObjectIDCoercion = true;
const AccessToken = app.models.AccessToken;
const UserIdentity = app.models.UserIdentity;

// 用户名唯一校验
User.validatesUniquenessOf('username', { message: 'username is not unique!' });

/**
 * 网页跳转登录
 */
app.post('/api/lssf/login', function (req, res, next) {
    // 通过referer判断跳转的来源网页是否合法
    var referer = req.headers.referer;
    if(referer == null) {
        return res.status(403).send({
            massage: "Illegal URL ! Please log in from http://lssf.cas.cn/"
        })
    }
    // 只允许从合肥光源用户实验管理系统跳转
    var srcUrl = 'http://localhost:4222';

    if(referer.search(srcUrl) == -1) {
        return res.status(403).send({
            massage: "Illegal URL ! Please log in from http://lssf.cas.cn/"
        })
    }
    var redirectUrl = req.body.redirectUrl;
    var start = redirectUrl.indexOf("=");
    var loginUsername = redirectUrl.substring(start+1);
    console.log("loginUsername: ", loginUsername);
    User.findOne(
        {
            where: {
                username: loginUsername
            }
        },
        function (err, user) {
            if (err) return next(err);
            if (user == null) {
                return res.status(422).send({
                    massage: "user is not exist !"
                })
            };
            var ttl = 1209600;
            user.createAccessToken(ttl, function (err, token) {
                if (err) return next(err);
                res.send(token);
            });
        })
});

/**
 * 在路由中间件中更新AccessToken，避免用户在操作中令牌过期
 */
// app.use(function(req, res, next) {
//     let token = req.accessToken;
//     if (!token) return next(); 
  
//     let now = new Date();
//     // for performance, you can drop it
//     if (now.getTime() - token.created.getTime() < 6000) return next();
//     token.updateAttribute('created', now, next);
//   });

/**
 * 将权限控制代码抽取出来作为路由中间件，提高可复用性
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
const acls = (req, res, next) => {
    // 自定义访问权限列表
    const allowArray = ['ingestor', 'globalaccess'];
    // 获得权限标识
    var flag = "";

    if (req.accessToken == null) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "AccessToken Invalid",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    };
    RoleMapping.find(
        {
            where: {
                principalId: String(
                    req.accessToken.userId
                )
            }
        },
        function (err, instances) {
            if (err) return next(err);
            if (instances == null) {
                var massage = {
                    "error": {
                        "statusCode": 401,
                        "name": "Error",
                        "message": "RoleMapping Invalid",
                        "code": "AUTHORIZATION_REQUIRED"
                    }
                };
                return res.status(401).send(massage);
            }
            const roleIdList = instances.map(
                instance => instance.roleId
            );
            Role.find(
                {
                    where: {
                        id: {
                            inq: roleIdList
                        }
                    }
                },
                function (err, result) {
                    if (err) return next(err);
                    const roleNameList = result.map(
                        instance => instance.name
                    );
                    // console.log('----roleNameList: ', roleNameList);
                    for (let i = 0; i < allowArray.length; i++) {
                        if (roleNameList.indexOf(allowArray[i]) > 0) {
                            // 激活权限标志位
                            flag = "allowUserManagement";
                            break;
                        };
                    }
                    req.flag = flag;
                    next();
                }
            );
        }
    );
}

// 在这里定义的路由，不会触发0-script.js中的strong-remoting phase代码

/**
 * 根据用户名查找所在的组 findUserGroups
 */
app.get('/api/findUserGroups', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }
    // console.log('--------accessToken: ', req.accessToken.userId);
    // console.log('--------userId: ', userId);
    User.findOne(
        {
            where: {
                username: req.query.username
            }
        },
        function (err, user) {
            if (err) return next(err);
            if (user == null) {
                return res.status(422).send({
                    massage: "user is not exist !"
                })
            }
            const userId = user.id;

            RoleMapping.find(
                {
                    where: {
                        principalId: String(
                            userId
                        )
                    }
                },
                function (err, instances) {
                    // console.log('--------RoleMapping, instances:', instances);
                    const roleIdList = instances.map(
                        instance => instance.roleId
                    );
                    //对每一个RoleMapping实例instances，将其roleId抽取出来，放到roleIdList数组
                    //关于map()的用法：https://www.jianshu.com/p/53032fc0909a

                    //https://loopback.io/doc/en/lb3/Where-filter.html#where-clause-for-queries
                    //inq运算符检查指定属性的值是否与数组中提供的任何值匹配。
                    Role.find(
                        {
                            where: {
                                id: {
                                    inq: roleIdList
                                }
                            }
                        },
                        function (err, result) {
                            if (err) return next(err);
                            const roleNameList = result.map(
                                instance => instance.name
                            );
                            // roleNameList.push(user.username);
                            // console.log('--------Role, roleNameList:', roleNameList);
                            res.send(roleNameList);
                            // cb(null, roleNameList);
                            //return roleNameList;
                        }
                    );
                }
            );
        });
});

/**
 * 根据用户名删除用户，以及RoleMapping，AccessToken，UserIdentity
 */
app.delete('/api/deleteUserByName', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }

    User.findOne(
        {
            where: {
                username: req.query.username
            }
        },
        function (err, user) {
            if (err) {
                throw err;
            }

            if (user == null) {
                return res.status(422).send({
                    massage: "user is not exist !"
                })
            }
            //   console.log('--------user: ', user);
            const userId = user.id;

            // destroyAll不能使用where等等filter，https://github.com/strongloop/loopback/issues/3094
            RoleMapping.destroyAll(
                {
                    principalId: String(userId)
                },
                function (err, instances) {
                    if (err) {
                        throw err;
                    }
                    //   console.log('--------RoleMapping: ', instances);
                }
            );

            AccessToken.destroyAll(
                {
                    userId: userId
                },
                function (err, instances) {
                    if (err) {
                        throw err;
                    }
                    //   console.log('--------AccessToken: ', instances);
                }
            );
            
            UserIdentity.destroyAll(
                {
                    userId: userId
                },
                function (err, instances) {
                    if (err) {
                        throw err;
                    }
                    //   console.log('--------UserIdentity: ', instances);
                }
            );

            User.destroyById(userId,
                function (err, instances) {
                    if (err) {
                        throw err;
                    }
                    //   console.log('--------User destroy: ', instances);
                    res.send(user.username);
                }
            );
        });

});

/**
 * 列出某个分组的所有用户
 */
app.get('/api/findGroupMember', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }

    Role.findOne(
        {
            where: {
                name: req.query.group
            }
        },
        function (err, role) {
            if (err) return next(err);
            if (role == null) {
                return res.status(422).send({
                    massage: "group is not exist !"
                })
            }
            
            const roleId = role.id;

            RoleMapping.find(
                {
                    where: {
                        roleId: String(
                            roleId
                        )
                    }
                },
                function (err, instances) {
                    if (err) return next(err);
                    const userIdList = instances.map(
                        instance => instance.principalId
                    );
                    User.find(
                        {
                            where: {
                                id: {
                                    inq: userIdList
                                }
                            }
                        },
                        function (err, result) {
                            if (err) return next(err);
                            const userNameList = result.map(
                                instance => instance.username
                            );
                            res.send(userNameList);
                        }
                    );
                }
            );
        });

});

/**
 * 根据组名删除分组
 */
app.delete('/api/deleteGroupByName', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }

    Role.findOne(
        {
          where: {
            name: req.query.group
          }
        }, 
        function(err, role) {
          if (err) {
            throw err;
          }
        
          if(role == null) {
            return res.status(422).send({
                massage: "group is not exist !"
            })
          }
          // console.log('--------user: ', user);
          const roleId = role.id;
  
          // destroyAll不能使用where等filter，https://github.com/strongloop/loopback/issues/3094
          RoleMapping.destroyAll(
            {
              roleId: roleId
            },
            function(err, instances) {
              if (err) {
                throw err;
              }
              // console.log('--------RoleMapping: ', instances);
            }
          );
  
          Role.destroyById(roleId, 
            function(err, instances) {
              if (err) {
                throw err;
              }
              // console.log('--------role destroy: ', instances);
              res.send(req.query.group + ' Deleted successfully');
            }
          );
      });
  

});

/**
 * 将用户分组（若用户或分组不存在，则新建）
 */
app.post('/api/connectUserAndGroups', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }

    var group = req.body.group;
    var userArray = req.body.users;
    if(group == '' || group == null || group == ' ' || userArray == null || userArray == [] || userArray == '') {
        return res.status(422).send({
            massage: "The group or users cannot be empty !"
        })
    }


    function addAccounts(userArray, index, next) {
        if (index < 0) {
            return res.status(200).send('Group updated successfully: ' + group);
        }

        var userName = userArray[index].userName;
        var data = {
            realm: 'lssf',
            username: userName,
            password: 'nsrl@scicat-' + userName,
            email: userArray[index].email,
            emailVerified: true
        }
        
        // create User if not yet there
        var filter = {
            where: {
                username: userName
            }
        }
        
        User.findOrCreate(filter, data, function (err, userinstance, created) {
            if (err) {
                console.log("Error when creating User:" + err + " " + userName)
                return next(err)
            } else {
                if (created) {
                    console.log("New account created:", userName);
                    // 创建关联的UserIdentity实例
                    var userIdentityData = {
                        "provider": "lssf",
                        "authScheme": "",
                        "externalId": userinstance.username,
                        "profile": {
                            "username": userinstance.username,
                            "receiverName": userArray[index].name,
                            "email": userinstance.email,
                            "accessGroups": [group],
                            "thumbnailPhoto": "",
                        },
                        "credentials": {},
                        "userId": userinstance.id
                    };
                    UserIdentity.create(userIdentityData, function (err, userIdentity) {
                        if (err) {
                            console.log("Error when creating UserIdentity:" + err + " " + userName)
                            return next(err)
                        };
                        // console.log("------userIdentity: ", userIdentity);
                    });
    
                } else {
                    console.log("User already exists:", userName);
                    // 更新用户的分组
                    UserIdentity.findOne(
                        {
                            where: {
                                userId: userinstance.id
                            }
                        },
                        function (err, userIdentity) {
                            if (err) {
                                console.log("Error when finding UserIdentity:" + err + " " + userName)
                                return next(err)
                            } else {
                                if (userIdentity.profile.accessGroups.indexOf(group) == -1) {
                                    userIdentity.profile.accessGroups.push(group);

                                    UserIdentity.updateAll(
                                        {
                                            id: userIdentity.id
                                        },
                                        {
                                            profile: userIdentity.profile
                                        },
                                        function (err, retUserIdentity) {
                                            if (err) {
                                                console.log("Error when update UserIdentity:" + err + " " + userName)
                                                return next(err)
                                            };
                                        }
                                    );
                                }
                            }
                        }
                    );
                }
                // and create role
                var role = group;
                var datarole = {
                    name: role
                }
                var filterrole = {
                    where: {
                        name: role
                    }
                }
                Role.findOrCreate(filterrole, datarole, function (err, roleinstance, created) {
                    if (err) {
                        console.log("Error when creating role:" + err + " " + role)
                        return next(err)
                    } else {
                        if (created) {
                            console.log("New role created:", role)
                        } else {
                            console.log("Role already exists:", role)
                        }
                        // and mapping
                        //check mapping exists first, maybe also look at user id?
    
                        var filtermapping = {
                            where: {
                                roleId: roleinstance.id,
                                principalId: String(userinstance.id)
                            }
                        }
                        var datamapping = {
                            principalType: RoleMapping.USER,
                            principalId: userinstance.id,
                            roleId: roleinstance.id
                        }
                        RoleMapping.findOrCreate(filtermapping, datamapping, function (err, mapinstance, created) {
                            if (err) {
                                console.log("Error when finding Rolemapping:" + err + " " + roleinstance.id, userinstance.id)
                                return next(err)
                            }
                            if (created) {
                                console.log("New rolemapping created:", role, userName)
                            } else {
                                console.log("Rolemapping already exists:", role, userName)
                            }
                            // res.send([username, role]);
                            index--
                            addAccounts(userArray, index, next)
                        });
                    }
                })
            }
        })
    }

    var index = userArray.length - 1;
    addAccounts(userArray, index, next)
});

/**
 * 从分组中删除用户
 */
app.delete('/api/deleteUserFromGroups', acls, (req, res, next) => {

    // 是否有权限
    const aclsMatchFlag = req.flag === "allowUserManagement";
    if (!aclsMatchFlag) {
        var massage = {
            "error": {
                "statusCode": 401,
                "name": "Error",
                "message": "Authorization Required",
                "code": "AUTHORIZATION_REQUIRED"
            }
        };
        return res.status(401).send(massage);
    }

    User.findOne(
        {
            where: {
                username: req.query.username
            }
        },
        function (err, user) {
            if (err) return next(err);
            if (user == null) {
                return res.status(422).send({
                    massage: "user is not exist !"
                });
            }
            // console.log('--------user: ', user);
            var userId = user.id;

            Role.findOne(
                {
                    where: {
                        name: req.query.group,
                    }
                },
                function (err, role) {
                    if (err) {
                        return next(err)
                    }
                    if (role == null) {
                        return res.status(422).send({
                            massage: "group is not exist !"
                        });
                    }
                    // console.log('--------role: ', role);
                    var roleId = role.id;

                    RoleMapping.destroyAll(
                        {
                            roleId: roleId,
                            principalId: String(userId)
                        },
                        function (err, instances) {
                            if (err) {
                                throw err;
                            }
                            // console.log('--------RoleMapping: ', instances);
                            if (instances.count > 0) {
                                // 更新用户的分组
                                UserIdentity.findOne(
                                    {
                                        where: {
                                            userId: userId
                                        }
                                    },
                                    function (err, userIdentity) {
                                        if (err) {
                                            console.log("Error when finding UserIdentity:" + err + " " + userName)
                                            return next(err)
                                        } else {
                                            var accessGroupsIndex = userIdentity.profile.accessGroups.indexOf(role.name);
                                            if (accessGroupsIndex != -1) {
                                                userIdentity.profile.accessGroups.splice(accessGroupsIndex, 1);
                                                UserIdentity.updateAll(
                                                    {
                                                        id: userIdentity.id
                                                    },
                                                    {
                                                        profile: userIdentity.profile
                                                    },
                                                    function (err, retUserIdentity) {
                                                        if (err) {
                                                            console.log("Error when update UserIdentity:" + err + " " + userName)
                                                            return next(err)
                                                        };
                                                        res.send('delete ' + user.username + ' from ' + role.name);
                                                    }
                                                );
                                            }
                                        }
                                    }
                                );
                            } else {
                                res.send(user.username + ' is not a member of ' + role.name);
                            }

                        }
                    );
                })
        }
    );

});

app.post('/api/test', (req, res, next) => {
    console.log('+++++++++ req.body:', req.body);
    res.send(req.body);
    // console.log('+++++++++ req.query:', req.query);
    // res.send(req.query);
});

app.get('/api/getTest', async (req, res, next) => {
    req.setTimeout(300*1000)
    console.log('++++ req query: ', req.query);
    var StoregeMate = {
        "size": 10240,
        "packedSize": 10240,
        "numberOfFiles": 2,
        "OrigDatablock_size": 10240,
        "dataFileList": [
          {
            "path": "/string1",
            "size": 5120,
            "time": "2021-01-20T02:43:04.985Z",
            "chk": "string",
            "uid": "string",
            "gid": "string",
            "perm": "string"
          },
          {
            "path": "/string2",
            "size": 5120,
            "time": "2021-01-20T02:45:04.985Z",
            "chk": "string",
            "uid": "string",
            "gid": "string",
            "perm": "string"
          }
        ]
      };
    console.log('++++ before sleep');
    await sleep(2*1000);
    console.log('++++ after sleep');
    res.send(StoregeMate);
});

// 代码延时
const sleep = (time) => {
    return new Promise(resolve => setTimeout(resolve, time))
  }
