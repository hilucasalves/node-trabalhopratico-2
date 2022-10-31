import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';

//Simulação do banco de dados
var users = {};

async function getUsers() {
  return users;
}

async function createUser(user) {
  const encryptedPwd = await bcrypt.hash(user.password, 10);

  users[user.username] = {
    password: encryptedPwd,
    role: user.role,
  };
  return user;
}

async function login(user) {
  const databaseUser = users[user.username];

  if (databaseUser) {
    const pwdMatches = bcrypt.compareSync(user.password, databaseUser.password);
    if (pwdMatches) {
      const privateKey = fs.readFileSync('./security/private.key');
      const token = await jwt.sign(
        { role: databaseUser.role, curso: 'Node,js' },
        privateKey,
        {
          expiresIn: 300,
          algorithm: 'RS256',
        }
      );
      return token;
    } else {
      throw new Error('Invalid Password');
    }
  } else {
    throw new Error('User not found');
  }
}

export default { getUsers, createUser, login };
