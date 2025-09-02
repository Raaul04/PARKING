import mongoose from "mongoose";

const SignatureSchema = new mongoose.Schema(
  {
    name:     { type: String, required: true, trim: true, maxlength: 140 },
    email:    { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
    district: { type: String, required: true, trim: true, maxlength: 120 },
    comment:  { type: String, trim: true, maxlength: 280 },
    verified: { type: Boolean, default: true }
  },
  { timestamps: true }
);

SignatureSchema.index({ email: 1 }, { unique: true });

export default mongoose.model("Signature", SignatureSchema);
