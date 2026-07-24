import Std

namespace StageA.Relational

inductive FiniteIndex (α : Type u) where
  | empty
  | leaf (values : List α)
  | branch (totalSize leftSize : Nat) (left right : FiniteIndex α)
deriving Repr, DecidableEq

namespace FiniteIndex

def ofListLeaf : List α -> FiniteIndex α
  | [] => .empty
  | values => .leaf values

def size : FiniteIndex α -> Nat
  | .empty => 0
  | .leaf values => values.length
  | .branch totalSize _ _ _ => totalSize

def toList : FiniteIndex α -> List α
  | .empty => []
  | .leaf values => values
  | .branch _ _ left right => left.toList ++ right.toList

def get? : FiniteIndex α -> Nat -> Option α
  | .empty, _ => none
  | .leaf values, index => values[index]?
  | .branch totalSize leftSize left right, index =>
      if totalSize <= index then none
      else if index < leftSize then left.get? index
      else right.get? (index - leftSize)

def append : FiniteIndex α -> FiniteIndex α -> FiniteIndex α
  | .empty, right => right
  | left, .empty => left
  | left, right => .branch (left.size + right.size) left.size left right

def height : FiniteIndex α -> Nat
  | .empty => 0
  | .leaf _ => 1
  | .branch _ _ left right => 1 + max left.height right.height

def sizesSound : FiniteIndex α -> Bool
  | .empty | .leaf _ => true
  | .branch totalSize leftSize left right =>
      totalSize == left.size + right.size &&
        leftSize == left.size && left.sizesSound && right.sizesSound

def leavesBounded (leafCapacity : Nat) : FiniteIndex α -> Bool
  | .empty => true
  | .leaf values => !values.isEmpty && values.length <= leafCapacity
  | .branch _ _ left right =>
      left.leavesBounded leafCapacity && right.leavesBounded leafCapacity

def branchesNonempty : FiniteIndex α -> Bool
  | .empty | .leaf _ => true
  | .branch _ _ left right =>
      left.size != 0 && right.size != 0 &&
        left.branchesNonempty && right.branchesNonempty

def balanced : FiniteIndex α -> Bool
  | .empty | .leaf _ => true
  | .branch _ _ left right =>
      left.height <= right.height + 1 && right.height <= left.height + 1 &&
        left.balanced && right.balanced

def structurallyValid (leafCapacity : Nat) (index : FiniteIndex α) : Bool :=
  index.sizesSound && index.leavesBounded leafCapacity &&
    index.branchesNonempty && index.balanced

def Contains (value : α) : FiniteIndex α -> Prop
  | .empty => False
  | .leaf values => value ∈ values
  | .branch _ _ left right => Contains value left ∨ Contains value right

instance : Membership α (FiniteIndex α) where
  mem index value := Contains value index

def containsDecidable [DecidableEq α] (value : α) :
    (index : FiniteIndex α) -> Decidable (Contains value index)
  | .empty => isFalse id
  | .leaf values => by
      simp only [Contains]
      infer_instance
  | .branch _ _ left right =>
      match containsDecidable value left with
      | isTrue found => isTrue (Or.inl found)
      | isFalse notLeft =>
          match containsDecidable value right with
          | isTrue found => isTrue (Or.inr found)
          | isFalse notRight => isFalse fun
              | Or.inl found => notLeft found
              | Or.inr found => notRight found

instance [DecidableEq α] (value : α) (index : FiniteIndex α) :
    Decidable (value ∈ index) := containsDecidable value index

instance : Coe (List α) (FiniteIndex α) where
  coe := ofListLeaf

instance : Coe (Array α) (FiniteIndex α) where
  coe values := ofListLeaf values.toList

instance : GetElem (FiniteIndex α) Nat α
    (fun index position => (index.get? position).isSome) where
  getElem index position valid := (index.get? position).get valid

theorem get?_eq_some_implies_lt_size (index : FiniteIndex α) (position : Nat)
    (value : α) (found : index.get? position = some value) :
    position < index.size := by
  cases index with
  | empty => simp [get?] at found
  | leaf values =>
      rcases List.getElem?_eq_some_iff.mp found with ⟨before, _⟩
      exact before
  | branch totalSize leftSize left right =>
      by_cases outside : totalSize <= position
      · simp [get?, outside] at found
      · simpa [size] using Nat.lt_of_not_ge outside

theorem get?_eq_some_implies_mem_toList (index : FiniteIndex α) (position : Nat)
    (value : α) (found : index.get? position = some value) :
    value ∈ index.toList := by
  induction index generalizing position with
  | empty => simp [get?] at found
  | leaf values =>
      have indexed := List.getElem?_eq_some_iff.mp found
      rcases indexed with ⟨inside, indexed⟩
      have member := List.getElem_mem inside
      rw [indexed] at member
      exact member
  | branch totalSize leftSize left right leftIH rightIH =>
      by_cases outside : totalSize <= position
      · simp [get?, outside] at found
      · by_cases inLeft : position < leftSize
        · simp [get?, outside, inLeft] at found
          exact List.mem_append_left _ (leftIH position found)
        · simp [get?, outside, inLeft] at found
          exact List.mem_append_right _ (rightIH (position - leftSize) found)

theorem toList_length_of_sizesSound
    (index : FiniteIndex α) (sizesSound : index.sizesSound = true) :
    index.toList.length = index.size := by
  induction index with
  | empty | leaf => rfl
  | branch totalSize leftSize left right leftIH rightIH =>
      simp only [FiniteIndex.sizesSound, Bool.and_eq_true, beq_iff_eq]
        at sizesSound
      simp [FiniteIndex.toList, FiniteIndex.size, List.length_append,
        leftIH sizesSound.1.2, rightIH sizesSound.2, sizesSound.1.1.1]

/-- A structurally sound finite index is an efficient representation of its
list projection, including out-of-bounds lookups.  Generated proofs use this
bridge to discharge point queries through the balanced index and retain the
existing list-based semantic interfaces. -/
theorem get?_eq_toList_get?
    (index : FiniteIndex α) (position : Nat)
    (sizesSound : index.sizesSound = true) :
    index.get? position = index.toList[position]? := by
  induction index generalizing position with
  | empty => rfl
  | leaf values => rfl
  | branch totalSize leftSize left right leftIH rightIH =>
      simp only [FiniteIndex.sizesSound, Bool.and_eq_true, beq_iff_eq]
        at sizesSound
      have totalExact : totalSize = left.size + right.size :=
        sizesSound.1.1.1
      have leftExact : leftSize = left.size := sizesSound.1.1.2
      have leftSound := sizesSound.1.2
      have rightSound := sizesSound.2
      by_cases outside : totalSize ≤ position
      · have listOutside : (left.toList ++ right.toList)[position]? = none := by
          apply List.getElem?_eq_none
          simpa [toList_length_of_sizesSound left leftSound,
            toList_length_of_sizesSound right rightSound, totalExact] using outside
        simp [FiniteIndex.get?, FiniteIndex.toList, outside, listOutside]
      · have inside : position < left.size + right.size := by omega
        by_cases inLeft : position < leftSize
        · have listLeft :
              (left.toList ++ right.toList)[position]? =
                left.toList[position]? := by
            apply List.getElem?_append_left
            simpa [toList_length_of_sizesSound left leftSound, leftExact]
              using inLeft
          simp [FiniteIndex.get?, FiniteIndex.toList, outside, inLeft,
            leftIH position leftSound, listLeft]
        · have afterLeft : left.toList.length ≤ position := by
            simpa [toList_length_of_sizesSound left leftSound, leftExact]
              using Nat.le_of_not_gt inLeft
          have notLeft : ¬ position < left.size := by
            simpa [leftExact] using inLeft
          have listRight :
              (left.toList ++ right.toList)[position]? =
                right.toList[position - left.toList.length]? := by
            exact List.getElem?_append_right afterLeft
          simp [FiniteIndex.get?, FiniteIndex.toList, outside, notLeft,
            leftExact, rightIH (position - left.size) rightSound, listRight,
            toList_length_of_sizesSound left leftSound]

theorem list_mem_implies_exists_get?
    (values : List α) (value : α) (member : value ∈ values) :
    ∃ position : Nat, values[position]? = some value := by
  induction values with
  | nil => simp at member
  | cons head tail induction =>
      simp only [List.mem_cons] at member
      rcases member with equal | member
      · subst head
        exact ⟨0, rfl⟩
      · obtain ⟨position, found⟩ := induction member
        exact ⟨position + 1, by simpa [List.getElem?_cons] using found⟩

theorem mem_toList_implies_exists_get?
    (index : FiniteIndex α) (value : α)
    (sizesSound : index.sizesSound = true)
    (member : value ∈ index.toList) :
    ∃ position, index.get? position = some value := by
  have listIndex :
      ∃ position : Nat, index.toList[position]? = some value :=
    list_mem_implies_exists_get? index.toList value member
  obtain ⟨position, found⟩ := listIndex
  refine ⟨position, ?_⟩
  rw [get?_eq_toList_get? index position sizesSound]
  exact found

@[simp] theorem size_ofListLeaf (values : List α) :
    (ofListLeaf values).size = values.length := by
  cases values <;> rfl

@[simp] theorem toList_ofListLeaf (values : List α) :
    (ofListLeaf values).toList = values := by
  cases values <;> rfl

@[simp] theorem size_append (left right : FiniteIndex α) :
    (left.append right).size = left.size + right.size := by
  cases left <;> cases right <;> simp [append, size]

@[simp] theorem toList_append (left right : FiniteIndex α) :
    (left.append right).toList = left.toList ++ right.toList := by
  cases left <;> cases right <;> simp [append, toList]

theorem sizesSound_append (left right : FiniteIndex α)
    (leftSound : left.sizesSound = true)
    (rightSound : right.sizesSound = true) :
    (left.append right).sizesSound = true := by
  cases left <;> cases right <;> simp_all [append, sizesSound, size]

theorem mem_iff_mem_toList (value : α) (index : FiniteIndex α) :
    value ∈ index ↔ value ∈ index.toList := by
  change Contains value index ↔ value ∈ index.toList
  induction index with
  | empty => simp [Contains, toList]
  | leaf values => simp [Contains, toList]
  | branch totalSize leftSize left right leftIH rightIH =>
      simp [Contains, toList, leftIH, rightIH]

end FiniteIndex

end StageA.Relational
