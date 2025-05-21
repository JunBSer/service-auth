package grpc

import (
	"context"
	"github.com/JunBSer/service-auth/internal/domain/models"
	"github.com/JunBSer/service-auth/internal/service"
	pb "github.com/JunBSer/services_proto/gen/go"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	srv service.AuthService
	pb.UnimplementedAuthServer
}

func NewService(srv *service.AuthService) *Service {
	return &Service{
		srv: *srv,
	}
}

func (srv *Service) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	aTkn, rTkn, err := srv.srv.Login(req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		Tokens: &pb.JWTPair{
			RefreshToken: rTkn,
			AccessToken:  aTkn,
		},
	}, nil
}

func (srv *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	usrId, err := srv.srv.Register(req.Email, req.Password, req.Name)
	if err != nil {
		return nil, err
	}

	return &pb.RegisterResponse{
		UserId: &pb.UUID{Value: usrId.String()},
	}, nil
}

func (srv *Service) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	err := srv.srv.Logout(req.RefreshToken)
	if err != nil {
		return &pb.LogoutResponse{
			Status: &pb.Status{
				Message: "Logout Unsuccessful",
				Success: false,
				Code:    400,
			},
		}, err
	}

	return &pb.LogoutResponse{
		Status: &pb.Status{
			Message: "Logout Success",
			Success: true,
			Code:    200,
		},
	}, nil
}

func (srv *Service) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	err := srv.srv.ChangePassword(req.OldPassword, req.NewPassword, req.AccessToken)
	if err != nil {
		return &pb.ChangePasswordResponse{
			Status: &pb.Status{
				Message: "Change Password Unsuccessful",
				Success: false,
				Code:    400,
			},
		}, err
	}

	return &pb.ChangePasswordResponse{
		Status: &pb.Status{
			Message: "Change Password Success",
			Success: true,
			Code:    200,
		},
	}, nil
}
func (srv *Service) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	aTkn, rTkn, err := srv.srv.RefreshToken(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	return &pb.RefreshResponse{
		Tokens: &pb.JWTPair{
			RefreshToken: rTkn,
			AccessToken:  aTkn,
		},
	}, nil
}

func (srv *Service) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.Status, error) {
	err := srv.srv.DeleteAccount(req.AccessToken, req.Password)
	if err != nil {
		return &pb.Status{
			Message: "Delete Account Unsuccessful",
			Success: false,
			Code:    400,
		}, err
	}

	return &pb.Status{
		Message: "Delete Account Success",
		Success: true,
		Code:    200,
	}, nil
}

func (srv *Service) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UserResponse, error) {
	userInfo, err := srv.srv.UpdateProfile(req.AccessToken, req.Email, req.Name)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{
		Name:    userInfo.Name,
		Email:   userInfo.Email,
		IsAdmin: userInfo.IsAdmin,

		CreatedAt: &timestamppb.Timestamp{
			Seconds: userInfo.CreatedAt.Unix(),
		},

		UserId: &pb.UUID{
			Value: userInfo.ID.String(),
		},
	}, nil
}

func (srv *Service) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	userID, err := srv.srv.ValidateToken(req.Token, service.JWT)
	if err != nil {
		return &pb.ValidateTokenResponse{
			UserId:  &pb.UUID{Value: uuid.Nil.String()},
			IsValid: false,
		}, err
	}

	return &pb.ValidateTokenResponse{
		UserId:  &pb.UUID{Value: userID.String()},
		IsValid: true,
	}, nil
}
func (srv *Service) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.UserResponse, error) {
	userInfo, err := srv.srv.CreateUser(&models.UserCrInfo{
		IsAdmin:  req.IsAdmin,
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{
		Name:    userInfo.Name,
		Email:   userInfo.Email,
		IsAdmin: userInfo.IsAdmin,

		CreatedAt: &timestamppb.Timestamp{
			Seconds: userInfo.CreatedAt.Unix(),
		},

		UserId: &pb.UUID{
			Value: userInfo.ID.String(),
		},
	}, nil
}

func (srv *Service) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	userInfo, err := srv.srv.GetUser(req.UserId)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{
		Name:    userInfo.Name,
		Email:   userInfo.Email,
		IsAdmin: userInfo.IsAdmin,

		CreatedAt: &timestamppb.Timestamp{
			Seconds: userInfo.CreatedAt.Unix(),
		},

		UserId: &pb.UUID{
			Value: userInfo.ID.String(),
		},
	}, nil
}

func (srv *Service) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	users, err := srv.srv.ListUsers(int(req.Page), int(req.Limit))
	if err != nil {
		return nil, err
	}

	userResponses := make([]*pb.UserResponse, len(users))

	for i, user := range users {
		userResponses[i] = &pb.UserResponse{
			Name:    user.Name,
			Email:   user.Email,
			IsAdmin: user.IsAdmin,

			CreatedAt: &timestamppb.Timestamp{
				Seconds: user.CreatedAt.Unix(),
			},

			UserId: &pb.UUID{
				Value: user.ID.String(),
			},
		}
	}

	return &pb.ListUsersResponse{
		Page:  req.Page,
		Users: userResponses,
		Total: int32(len(userResponses)),
	}, nil
}

func (srv *Service) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	userInfo, err := srv.srv.UpdateUser(&models.UserChInfo{
		IsAdmin:  req.IsAdmin,
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{
		Name:    userInfo.Name,
		Email:   userInfo.Email,
		IsAdmin: userInfo.IsAdmin,

		CreatedAt: &timestamppb.Timestamp{
			Seconds: userInfo.CreatedAt.Unix(),
		},

		UserId: &pb.UUID{
			Value: userInfo.ID.String(),
		},
	}, nil
}

func (srv *Service) DeleteUser(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	err := srv.srv.DeleteUser(req.UserId)
	if err != nil {
		return &pb.DeleteResponse{
			Status: &pb.Status{
				Message: "Delete User Unsuccessful",
				Success: false,
				Code:    400,
			},
		}, err
	}

	return &pb.DeleteResponse{
		Status: &pb.Status{
			Message: "Delete User Success",
			Success: true,
			Code:    200,
		},
	}, nil
}
