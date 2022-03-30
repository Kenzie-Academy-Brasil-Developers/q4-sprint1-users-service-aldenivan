import express from 'express';
import { v4 } from 'uuid';
import * as yup from 'yup';
import jsonwebtoken from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const USERS = [];
const PORT = 3000;

app.use(express.json());

const config = {
  secretKey: 'xablauzinho',
  expiresIn: '1h',
};

const createUserShape = yup.object().shape({
  uuid: yup.string().default(() => v4()),
  username: yup.string().required(),
  email: yup.string().email().required(),
  age: yup.number().positive().integer().required(),
  password: yup
    .string()
    .min(8)
    .required()
    .transform((pws) => bcrypt.hashSync(pws, 10)),
  createdOn: yup.string().default(() => Date()),
});

const loginShape = yup.object().shape({
  email: yup.string().email().required(),
  password: yup.string().min(8).required(),
});

const updateUserPasswprdShape = yup.object().shape({
  password: yup.string().min(8).required(),
});

const getUser = (req, res, next) => {
  const { uuid } = req.params;
  const user = USERS.find((u) => u.uuid === uuid);

  if (!user) {
    return res.status(404).json({ message: 'user not found!' });
  }

  req.user = user;

  return next();
};

const validateShapes = (shape) => async (req, res, next) => {
  try {
    const validated = await shape.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });
    req.validated = validated;
    return next();
  } catch (err) {
    return res.status(422).json({ error: err.errors });
  }
};

const validateAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  jsonwebtoken.verify(token, config.secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: err });
    }

    req.email = decoded.email;
    return next();
  });
};

const verifyUserPermission = (req, res, next) => {
  const { user, email } = req;

  if (user.email !== email) {
    return res.status(401).json({ error: 'unauthorazed' });
  }

  return next();
};

app.post('/signup', validateShapes(createUserShape), async (req, res) => {
  const user = { ...req.validated };
  const showUser = { ...req.validated };
  delete showUser.password;

  if (USERS.find((_) => _.email === user.email)) {
    return res.status(409).json({ error: 'Email already exixt' });
  }

  USERS.push(user);
  res.status(201).json(showUser);
});

app.post('/login', validateShapes(loginShape), async (req, res) => {
  const { email } = req.validated;
  const user = USERS.filter((_) => email === _.email);

  if (!user) {
    return res.status(400).json({ error: 'Invalidated credentials' });
  }

  // const hasedPassword = await bcrypt.compare(req.body.password, user.password);

  // if (!hasedPassword) {
  //   return res.status(400).json({ error: 'Invalidated credentials' });
  // }

  const token = jsonwebtoken.sign({ email }, config.secretKey, {
    expiresIn: config.expiresIn,
  });

  return res.status(200).json({ token });
});

app.put(
  '/users/:uuid/password',
  validateShapes(updateUserPasswprdShape),
  validateAuth,
  getUser,
  verifyUserPermission,
  (req, res) => {
    const { password } = req.body;
    const { user } = req;

    user.password = password;

    return res.status(204).json(user);
  }
);

app.get('/users', (_, res) => {
  return res.status(200).json(USERS);
});

app.listen(PORT, () => console.log(`App running in port ${PORT}`));
