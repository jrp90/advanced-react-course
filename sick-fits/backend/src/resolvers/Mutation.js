const bycrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Mutation = {
  async createItem(parent, args, ctx, info) {
    // TODO: Check if they are logged in

    const item = await ctx.db.mutation.createItem(
      {
        data: {
          ...args
        }
      },
      info
    );

    return item;
  },
  updateItem(parent, args, ctx, info) {
    // Take a copy of the updates
    const updates = { ...args };

    // Remove the ID from the updates
    delete updates.id;

    // Run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };

    //Find the Item
    const item = await ctx.db.query.item({ where }, `{ id, title}`);

    //Check if they own the item, or have the permissions
    // TODO

    //Delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();

    // hash their password
    const password = await bycrypt.hash(args.password, 10);

    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      { data: { ...args, password, permissions: { set: ['USER'] } } },
      info
    );

    // create a JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);

    // Set the JWT as a cookie on the response
    ctx.response.cookie('token', token, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 365 });

    // Return user to browser
    return user;
  }
};

module.exports = Mutation;
