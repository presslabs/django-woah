# django-woah
An opinionated package intended to help Django developers implement an authorization system for their apps.

## What it can do
- It can handle Organizations, Teams (including nesting sub-teams to some degree) and Memberships (including outside collaborators)
- It can handle per user, as well as Organization-wide and Team-wide privileges
- It can handle per object, as well as per model Privileges
- It can filter the resources on which a (single) actor is authorized (most of the time, with 2 DB queries), based on the defined AuthorizationSchemes, given a set of permissions to check
- It offers some built-in support for Django REST Framework (DRF).
- Authorization Schemes are based on Python classes. They don't strictly follow pre-existing authorization patterns, such as ABAC or (P)RBAC, but they offer a pragmatic approach that resembles a mix of those.

For what it can not do, check the [shortcomings](#shortcomings).


## How it looks

Say you are making an issue tracker kind of app, and your model looks something like this:
```python
# my_app/issue_tracker/models.py
class Issue(models.Model):
    owner = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="owned_issues"
    )
    author = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="authored_issues",
    )
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="issues"
    )
    title = models.CharField(max_length=512)
    content = models.TextField()
    state = models.CharField(max_length=16, default=IssueState.OPEN)
```

Let's define an AuthorizationScheme, starting with some CRUD permissions, one to close/reopen issues, and also an Issue Manager role:
```python
# my_app/issue_tracker/authorization.py
# Here you can define authorization schemes for your models
from django_woah.authorization import AuthorizationScheme, PermEnum

class IssueAuthorizationScheme(AuthorizationScheme):
    model = Issue

    class Perms(PermEnum):
        ISSUE_VIEW = "issue:issue_view"
        ISSUE_CREATE = "issue:issue_create"
        ISSUE_EDIT_CONTENT = "issue:issue_edit_content"
        ISSUE_CHANGE_STATE = "issue:issue_change_state"
        ISSUE_DELETE = "issue:issue_delete"

    class Roles(PermEnum):
        ISSUE_MANAGER = "issue:manager"
```

We want our Issue Manager role to receive all the permissions above, so we are going to append some indirect permissions logic to our IssueAuthorizationScheme:
```python
# my_app/issue_tracker/authorization.py
from django_woah.authorization import (
    # [...]
    IndirectPerms, ConditionalPerms, HasSameResourcePerms,
)

class IssueAuthorizationScheme(AuthorizationScheme):
    # [...]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    HasSameResourcePerms([self.Roles.ISSUE_MANAGER]),
                ],
                receives_perms=self.Perms.values(),
            ),
        ]
```

Now we might want to ensure that only members/collaborators of the same organization that owns the issue may receive authorization. For that we must establish the owner_relation (field) of the Issue model, and set up an implicit condition that will be our Membership check.
```python
# my_app/issue_tracker/authorization.py

class IssueAuthorizationScheme(AuthorizationScheme):
    # [...]
    owner_relation = "owner"  # this references the owner ForeignKey field in our Issue model 

    def get_implicit_conditions(
        self, context: Context
    ) -> list[Condition]:
        return [
            HasRootMembership(actor=context.actor),
        ]
    
    # [...]
```

Noticed the `project` field in the `Issue` model? It can be used to organize a bunch of issues. Let's say we want to allow assigning permissions project-wide. For that we need to append another way of obtaining Indirect Permissions:
```python
# my_app/issue_tracker/authorization.py
from django_woah.authorization import (
    # [...]
    TransitiveFromRelationPerms,
)

class IssueAuthorizationScheme(AuthorizationScheme):
    # [...]
    
    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            # [...],
            # You'd need to have a ProjectAuthorizationScheme in place for
            # this to properly work, but it's out of scope for this example.
            TransitiveFromRelationPerms(
                relation="project",
            ),
        ]
```

What if we want to allow authors to manage their own issues a bit?
```python
from django_woah.authorization import QCondition
# [...]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            # [...],
            QCondition(
                conditions=[
                    # The implicit membership condition we defined above,
                    # will still apply, so if the author were to lose
                    # membership, this condition will not apply anymore.
                    QCondition(Q(author=context.actor)),
                ],
                receives_perms=[
                  self.Perms.ISSUE_VIEW,
                  self.Perms.ISSUE_EDIT_CONTENT,
                  self.Perms.ISSUE_CHANGE_STATE,
                ],
            ),
        ]
```
To see more code in action you can check the [examples](django-woah/examples), or read about [how it all works](#how-it-all-works).


## How it all works, in short
- UserGroups represent, as the name implies, a group of users; for convenience these can be used to represent a single user, a Team, or the entirety of members/collaborators of an organization/account
- Memberships are used to represent a Django User's membership into the aforementioned UserGroups
- Privileges are the relation between a UserGroup (actors), a Perm/Role and a Model or an object
- AuthorizationSchemes define what actors are allowed to do, and under what Conditions.
  - These contain Permissions definitions; Roles can be defined separately but they are permissions too
  - Users can dynamically be given additional Privileges based on Conditions
  - Or implicit Conditions can be defined to apply to then entire Scheme, including for the Privileges stored in the database
- A Context consists mostly of an actor, permissions and a resource, and is used when enforcing authorizations.
- An AuthorizationSolver works over the user-defined AuthorizationSchemes, and it is used for enforcing authorization, requiring a Context.


## Performance
- Although proper benchmarks haven't been conducted, performance should be decent. Most authorization checks can be done with 2 queries (if the actor has already been fetched, as is usually the case with local authentication): one to fetch Privileges, and one to filter the resources on which the actor is authorized


## Current status and future plans
- Although the library hasn't reached version 1.0 yet, it is being used in production at Presslabs.
- This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). That means until version 1.0, breaking changes are to be expected from one version to another, although they will be documented in the [changelog](CHANGELOG.MD).
- There is a good chance for pre-release versions to be maintained for a while, in terms of compatibility with newer Django and Python versions, as well as critical bugfixes. You might have to contribute with a pull request yourself though, but we'll at least review it and include it in a new release.


## Shortcomings
The abstractions around how Conditions are composed and relate to AuthorizationSchemes/Solver could've been more inspired... A rework might happen before the 1.0 release, but chances are it will have to wait until a 2.0 release, or somewhere down the line, as the API is *usable* enough... just kind of rough around the edges:

- It's hard (and not performant) to interrogate whom all the user with privileges on a resource or a set of resources are.
- It's not possible to define and store new permissions/roles in the DB.
- It's cumbersome or downright hard to interrogate by specific *Conditions*
- Verifying permissions on already prefetched resources, in cases where conditions can be satisfied without checking privileges, or privileges have been prefetched as well, could be more performant. The best way of doing it now is filtering for which of them is satisfy authorization, as if they weren't prefetched to begin with.
- For some cases, prefetching Privileges could be avoided, and the whole authorization interrogation could be done with a single query... but not with how the abstraction is currently built. That single query would consist of more DB joins, so it's hard to tell if a potential performance increase is left on the table or not, without actual benchmarks.
- Memberships could be made more optional in the whole design, but it's not clear if that's of any importance right now.
- Some "meta" indirect privileges are hard (or even impossible) to implement, especially in a performant manner. For example: giving privileges that other users possess, based on a relation between the actor and the respective users, if say they are part of the same UserGroups. 
- This library is mostly intended to be used in conjunction with APIs. There is (currently) no built-in support for the Django Admin, and no plan to add one unless there is enough interest for it and somebody contributes it. 
- Some may not like that Authorization Schemes are based on Python classes, and not on some configuration system.

If these are dealbreakers for you or you are simply looking for something else, check the [alternatives](#alternatives).


## Alternatives
- https://github.com/pycasbin/django-authorization
- https://github.com/dimagi/django-prbac
- https://github.com/osohq/oso/tree/main/languages/python/django-oso/ (deprecated, but not EoL-ed for, it seems)
