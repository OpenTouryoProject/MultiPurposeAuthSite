using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

// http://mrgchr.hatenablog.com/entry/2016/11/29/000000

namespace MultiPurposeAuthSite
{
    public class ApplicationUser
    {
        public ApplicationUser()
        {
            Id = Guid.NewGuid();
        }

        public ApplicationUser(string userName) : this()
        {
            UserName = userName;
        }

        public Guid Id { get; set; }
        public string UserId => Id.ToString();

        public string UserName { get; set; }
        public string NormalizedUserName { get; set; }
                
        public string PasswordHash { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        
        public string PhoneNumber { get; set; }

        public bool TwoFactorEnabled { get; set; }

        public string ScreenName { get; set; }
    }

    public class ApplicationRole
    {
        public Guid Id { get; set; }

        public string Name { get; set; }
    }

    public class UserStore : IUserStore<ApplicationUser>, IUserPasswordStore<ApplicationUser>
    {
        private static readonly List<ApplicationUser> InMemoryStore = new List<ApplicationUser>();

        public void Dispose() { }

        public async Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
            => user.Id.ToString();

        public async Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
            => user.UserName;

        public async Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
            => user.UserName = userName;

        public async Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
            => user.NormalizedUserName;

        public async Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
            => user.NormalizedUserName = normalizedName;

        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            InMemoryStore.Add(user);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            var index = InMemoryStore.FindIndex(a => a.Id == user.Id);
            InMemoryStore[index] = user;
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            var index = InMemoryStore.FindIndex(a => a.Id == user.Id);
            InMemoryStore.RemoveAt(index);
            return IdentityResult.Success;
        }

        public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken) =>
            InMemoryStore.FirstOrDefault(a => a.Id.ToString() == userId);

        public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) =>
            InMemoryStore.FirstOrDefault(a => a.NormalizedUserName == normalizedUserName);

        public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
            => user.PasswordHash = passwordHash;

        public async Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
            => user.PasswordHash;

        public async Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
            => true;
    }

    public class RoleStore : IRoleStore<IdentityRole>
    {
        public void Dispose() { }

        public Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<string> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task SetRoleNameAsync(IdentityRole role, string roleName, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<string> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task SetNormalizedRoleNameAsync(IdentityRole role, string normalizedName, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<IdentityRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public Task<IdentityRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
            => throw new NotImplementedException();
    }
}
