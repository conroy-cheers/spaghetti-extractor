import Std

namespace StageA.Formal

abbrev Byte := Nat
abbrev Bytes := List Byte
inductive ByteTree where
  | empty
  | leaf (bytes : Bytes)
  | node (size leftSize : Nat) (left right : ByteTree)
deriving Repr, DecidableEq

def ByteTree.length : ByteTree -> Nat
  | .empty => 0
  | .leaf bytes => bytes.length
  | .node size _ _ _ => size

def ByteTree.mergeRound : List ByteTree -> List ByteTree
  | left :: right :: rest =>
      .node (left.length + right.length) left.length left right :: mergeRound rest
  | rest => rest

def ByteTree.build : Nat -> List ByteTree -> ByteTree
  | _, [] => .empty
  | _, [tree] => tree
  | 0, tree :: _ => tree
  | fuel + 1, trees => build fuel (mergeRound trees)

def ByteTree.chunkBytes (chunkSize : Nat) : Nat -> Bytes -> List Bytes
  | 0, _ => []
  | _, [] => []
  | fuel + 1, bytes =>
      bytes.take chunkSize :: chunkBytes chunkSize fuel (bytes.drop chunkSize)

def ByteTree.ofBytes (bytes : Bytes) : ByteTree :=
  let chunkSize := 1024
  let count := (bytes.length + chunkSize - 1) / chunkSize
  let leaves := (ByteTree.chunkBytes chunkSize count bytes).map ByteTree.leaf
  ByteTree.build count leaves

def ByteTree.readByte : ByteTree -> Nat -> Option Byte
  | .empty, _ => none
  | .leaf bytes, offset => bytes[offset]?
  | .node size leftSize left right, offset =>
      if offset >= size then none
      else if offset < leftSize then left.readByte offset
      else right.readByte (offset - leftSize)

def ByteTree.readBytes (tree : ByteTree) : Nat -> Nat -> Option Bytes
  | _, 0 => some []
  | offset, count + 1 => do
      let head <- tree.readByte offset
      let tail <- tree.readBytes (offset + 1) count
      pure (head :: tail)

def readByte (bytes : Bytes) (offset : Nat) : Option Byte :=
  (bytes.drop offset).head?

def readU16 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let b0 <- readByte bytes offset
  let b1 <- readByte bytes (offset + 1)
  if b0 < 256 && b1 < 256 then
    pure (b0 + b1 * 256)
  else
    none

def readU32 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let lo <- readU16 bytes offset
  let hi <- readU16 bytes (offset + 2)
  pure (lo + hi * 65536)


end StageA.Formal
