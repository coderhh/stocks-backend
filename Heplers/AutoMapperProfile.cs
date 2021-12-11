using AutoMapper;
using stocks_backend.Entities;
using stocks_backend.Models.Accounts;

namespace stocks_backend.Heplers
{
    public class AutoMapperProfile: Profile
    {
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            CreateMap<Account, AccountResponse>();
            CreateMap<RegisterRequest, Account>();
        }
    }
}