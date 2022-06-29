const { Schema, model } = require("mongoose");

// TODO: Please make sure you edit the user model to whatever makes sense in this case
const userSchema = new Schema(
  {
    username: {
      type: String,
      trim: true,
      required: [true, 'Username is required.'],
      unique: true
    },
    email: {
      type: String,
      required: [true, 'Email is required.'],
      /* este 'match' descalificará todos los correos electrónicos con espacios vacíos
       accidentales, puntos faltantes delante de (.)com y los que no tengan ningún dominio*/
      match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address.'], 
      unique: true,
      lowercase: true,
      trim: true
    },
    passwordHash: {
      type: String,
      required: [true, 'Password is required.']
    }
  },
  {
    timestamps: true
  }
);

const User = model("User", userSchema);

module.exports = User;

