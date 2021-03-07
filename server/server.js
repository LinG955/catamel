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

    // 通过referer判断请求是否合法，只允许来自SciCat前端catanie的调用该接口
    var referer = req.headers.referer;
    if (referer == null || referer.search('http://localhost:4222') == -1) {
        return res.status(403).send({
            massage: "Illegal URL ! Please log in from http://lssf.cas.cn/"
        })
    }

    // 取出url后面的参数，判断参数数量是否与约定的相同
    var paramsArr = req.body.redirectUrl.split('?').pop().split('&');
    if (paramsArr.length != 3) {
        return res.status(403).send({
            massage: "Illegal URL ! Please log in from http://lssf.cas.cn/"
        })
    }
    // 将参数封装成json
    var paramsObj = {};
    paramsObj.username = paramsArr[0].split('=').pop();
    paramsObj.email = paramsArr[1].split('=').pop();
    paramsObj.searchGroup = paramsArr[2].split('=').pop();
    if (paramsObj.searchGroup === "All") {
        paramsObj.searchGroup = "";
    }

    User.findOne(
        {
            where: {
                username: paramsObj.username
            }
        },
        function (err, user) {
            if (err) return next(err);
            if (user == null) {
                return res.status(422).send({
                    massage: "user is not exist !"
                })
            };
            // 登录过期时间为10分钟
            var ttl = 600;
            user.createAccessToken(ttl, function (err, token) {
                if (err) return next(err);
                // 在返回的AccessToken中，添加前端dataset搜索所需的过滤条件searchGroup
                token.searchGroup = paramsObj.searchGroup;
                res.send(token);
            });
        })
});

/**
 * 在路由中间件中更新AccessToken，避免用户在操作中令牌过期
 */
app.use(function(req, res, next) {
    let token = req.accessToken;
    if (!token) return next(); 
  
    let now = new Date();
    // 有效期少于2分钟则更新令牌
    if (now.getTime() - token.created.getTime() < 120000) return next();
    token.updateAttribute('created', now, next);
  });

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

/**
 * 根据用户名或ID查找所在的组 findUserGroups
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
    var userFilter = {};
    if (!!req.query.username) {
        userFilter = {
            where: {
                username: req.query.username
            }
        }
    } else {
        userFilter = {
            where: {
                id: req.query.userId
            }
        }
    }
    User.findOne(
        userFilter,
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
            "path": "file1",
            "size": 5120,
            "time": "2021-01-20T02:43:04.985Z",
            "chk": "string",
            "uid": "string",
            "gid": "string",
            "perm": "string"
          },
          {
            "path": "file2",
            "size": 5120,
            "time": "2021-01-20T02:45:04.985Z",
            "chk": "string",
            "uid": "string",
            "gid": "string",
            "perm": "string"
          }
        ],
        "attachments": [
            {
                "thumbnail": "data:image/png;base64,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",
                "caption": "attachment-township"
            },
            {
                "thumbnail": "data:image/jpeg;base64,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",
                "caption": "attachment-dog"
            },
            {
                "thumbnail": "data:image/png;base64,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",
                "caption": "attachment-linux"
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
