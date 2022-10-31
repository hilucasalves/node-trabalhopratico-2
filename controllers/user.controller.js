import UserService from '../services/user.service.js';

async function getUsers(req, res, next) {
  try {
    res.send(await UserService.getUsers());
    logger.info('GET /getUsers');
  } catch (err) {
    next(err);
  }
}

async function createUser(req, res, next) {
  try {
    let user = req.body;
    if (!user.username || user.password == null || user.role == null) {
      throw new Error('Username, Password e Role são obrigatórios.');
    }
    user = await UserService.createUser(user);

    res.status(201).json({ message: `User ${user.username} created.` });

    logger.info(`POST /createUser - ${JSON.stringify(user)}`);
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    let user = req.body;
    if (!user.username || user.password == null) {
      throw new Error('Username e Password são obrigatórios.');
    }
    res.send(await UserService.login(user));

    logger.info(`POST /login - ${JSON.stringify(user)}`);
  } catch (err) {
    next(err);
  }
}

export default {
  getUsers,
  createUser,
  login,
};
