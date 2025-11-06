#  Copyright 2025 Pressinfra SRL
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from enum import StrEnum
from typing import Generic, Self, T


class OP(StrEnum):
    AND = "and"
    OR = "or"


class TruthBearer(Generic[T]):
    # Class is subject to change

    def __init__(self, *args: T, operator=OP.AND, truth=True):
        # TODO: Maybe rename self.truth to self.boolean or something similar, since Unauthorized always returning False
        #       sounds like a double negation and may lead to confusion.
        self.truth = truth
        self.operator = operator
        self.identity: tuple[T, ...] = tuple(args)

    def __neg__(self) -> Self:
        return self.__class__(*self.identity, operator=self.operator, truth=not self.truth)

    def __repr__(self):
        return f"{self.identity}: {self.truth}"

    def __str__(self):
        return f"{self.identity}: {self.truth}"

    def __hash__(self):
        return ((self.truth, self.operator) + self.identity).__hash__()

    def __eq__(self, other: "TruthBearer"):
        if not isinstance(other, TruthBearer):
            return False

        return self.truth == other.truth and self.operator == other.operator and self.identity == other.identity


class Atom(TruthBearer):
    def get_atoms(self) -> set[Self]:
        return {self}


class Sentence(TruthBearer[Atom]):
    def get_atoms(self) -> set[Atom]:
        atoms = set()
        for element in self.identity:
            if isinstance(element, Atom):
                atoms.add(element)
            else:
                atoms = atoms.union(element.get_atoms())

        return atoms


class KnowledgeBase:
    def __init__(self, *args: Atom | Sentence):
        self.atoms: set[Atom] = set()
        self.known: set[Atom | Sentence] = set()

        self.add(*args)

    def add(self, *args: Atom | Sentence):
        for arg in args:
            if isinstance(arg, Atom):
                if arg in self.known:
                    continue

                if -arg in self.known:
                    raise ValueError(f"Found Atom in knowledgebase with opposite truth: {arg}")

            self.known.add(arg)
            for atom in arg.get_atoms():
                self.atoms.add(atom)

    def check(self, arg: Atom | Sentence) -> Atom | None:
        if arg in self.known:
            return arg

        if -arg in self.known:
            return -arg
